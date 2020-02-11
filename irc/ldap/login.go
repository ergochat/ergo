// Copyright (c) 2020 Matt Ouille
// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

// Portions of this code copyright Grafana Labs and contributors
// and released under the Apache 2.0 license

// Copying Grafana's original comment on the different cases for LDAP:
// There are several cases -
// 1. "admin" user
// Bind the "admin" user (defined in Grafana config file) which has the search privileges
// in LDAP server, then we search the targeted user through that bind, then the second
// perform the bind via passed login/password.
// 2. Single bind
// // If all the users meant to be used with Grafana have the ability to search in LDAP server
// then we bind with LDAP server with targeted login/password
// and then search for the said user in order to retrive all the information about them
// 3. Unauthenticated bind
// For some LDAP configurations it is allowed to search the
// user without login/password binding with LDAP server, in such case
// we will perform "unauthenticated bind", then search for the
// targeted user and then perform the bind with passed login/password.

// Note: the only validation we do on users is to check RequiredGroups.
// If RequiredGroups is not set and we can do a single bind, we don't
// even need to search. So our case 2 is not restricted
// to setups where all the users have search privileges: we only need to
// be able to do DN resolution via pure string substitution.

package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"

	"github.com/oragono/oragono/irc/logger"
)

var (
	ErrCouldNotFindUser       = errors.New("No such user")
	ErrUserNotInRequiredGroup = errors.New("User is not a member of any required groups")
	ErrInvalidCredentials     = errors.New("Invalid credentials")
)

func CheckLDAPPassphrase(config LDAPConfig, accountName, passphrase string, log *logger.Manager) (err error) {
	defer func() {
		if err != nil {
			log.Debug("ldap", "failed passphrase check", err.Error())
		}
	}()

	l, err := dial(&config)
	if err != nil {
		return
	}
	defer l.Close()

	l.SetTimeout(config.Timeout)

	passphraseChecked := false

	if config.shouldSingleBind() {
		log.Debug("ldap", "attempting single bind to", accountName)
		err = l.Bind(config.singleBindDN(accountName), passphrase)
		passphraseChecked = (err == nil)
	} else if config.shouldAdminBind() {
		log.Debug("ldap", "attempting admin bind to", config.BindDN)
		err = l.Bind(config.BindDN, config.BindPassword)
	} else {
		log.Debug("ldap", "attempting unauthenticated bind")
		err = l.UnauthenticatedBind(config.BindDN)
	}

	if err != nil {
		return
	}

	if passphraseChecked && len(config.RequireGroups) == 0 {
		return nil
	}

	users, err := lookupUsers(l, &config, accountName)
	if err != nil {
		log.Debug("ldap", "failed user lookup")
		return err
	}

	if len(users) == 0 {
		return ErrCouldNotFindUser
	}

	user := users[0]

	log.Debug("ldap", "looked up user", user.DN)

	err = validateGroupMembership(l, &config, user, log)
	if err != nil {
		return err
	}

	if !passphraseChecked {
		// Authenticate user
		log.Debug("ldap", "rebinding", user.DN)
		err = l.Bind(user.DN, passphrase)
		if err != nil {
			log.Debug("ldap", "failed rebind", err.Error())
			if ldapErr, ok := err.(*ldap.Error); ok {
				if ldapErr.ResultCode == 49 {
					return ErrInvalidCredentials
				}
			}
		}
		return err
	}

	return nil
}

func dial(config *LDAPConfig) (conn *ldap.Conn, err error) {
	var certPool *x509.CertPool
	if config.RootCACert != "" {
		certPool = x509.NewCertPool()
		for _, caCertFile := range strings.Split(config.RootCACert, " ") {
			pem, err := ioutil.ReadFile(caCertFile)
			if err != nil {
				return nil, err
			}
			if !certPool.AppendCertsFromPEM(pem) {
				return nil, errors.New("Failed to append CA certificate " + caCertFile)
			}
		}
	}
	var clientCert tls.Certificate
	if config.ClientCert != "" && config.ClientKey != "" {
		clientCert, err = tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
		if err != nil {
			return
		}
	}
	for _, host := range strings.Split(config.Host, " ") {
		address := fmt.Sprintf("%s:%d", host, config.Port)
		if config.UseSSL {
			tlsCfg := &tls.Config{
				InsecureSkipVerify: config.SkipTLSVerify,
				ServerName:         host,
				RootCAs:            certPool,
			}
			if len(clientCert.Certificate) > 0 {
				tlsCfg.Certificates = append(tlsCfg.Certificates, clientCert)
			}
			if config.StartTLS {
				conn, err = ldap.Dial("tcp", address)
				if err == nil {
					if err = conn.StartTLS(tlsCfg); err == nil {
						return
					}
				}
			} else {
				conn, err = ldap.DialTLS("tcp", address, tlsCfg)
			}
		} else {
			conn, err = ldap.Dial("tcp", address)
		}

		if err == nil {
			return
		}
	}
	return
}

func validateGroupMembership(conn *ldap.Conn, config *LDAPConfig, user *ldap.Entry, log *logger.Manager) (err error) {
	if len(config.RequireGroups) != 0 {
		var memberOf []string
		memberOf, err = getMemberOf(conn, config, user)
		if err != nil {
			log.Debug("ldap", "could not retrieve group memberships", err.Error())
			return
		}
		log.Debug("ldap", fmt.Sprintf("found group memberships: %v", memberOf))
		foundGroup := false
		for _, inGroup := range memberOf {
			for _, acceptableGroup := range config.RequireGroups {
				if inGroup == acceptableGroup {
					foundGroup = true
					break
				}
			}
			if foundGroup {
				break
			}
		}
		if !foundGroup {
			return ErrUserNotInRequiredGroup
		}
	}
	return nil
}

func lookupUsers(conn *ldap.Conn, config *LDAPConfig, accountName string) (results []*ldap.Entry, err error) {
	var result *ldap.SearchResult

	for _, base := range config.SearchBaseDNs {
		result, err = conn.Search(
			getSearchRequest(config, base, accountName),
		)
		if err != nil {
			return nil, err
		} else if len(result.Entries) > 0 {
			return result.Entries, nil
		}
	}

	return nil, nil
}

// getSearchRequest returns LDAP search request for users
func getSearchRequest(
	config *LDAPConfig,
	base string,
	accountName string,
) *ldap.SearchRequest {

	var attributes []string
	if config.MemberOfAttribute != "" {
		attributes = []string{config.MemberOfAttribute}
	}

	query := strings.Replace(
		config.SearchFilter,
		"%s", ldap.EscapeFilter(accountName),
		-1,
	)

	return &ldap.SearchRequest{
		BaseDN:       base,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Attributes:   attributes,
		Filter:       query,
	}
}

// getMemberOf finds memberOf property or request it
func getMemberOf(conn *ldap.Conn, config *LDAPConfig, result *ldap.Entry) (
	[]string, error,
) {
	if config.GroupSearchFilter == "" {
		memberOf := getArrayAttribute(config.MemberOfAttribute, result)

		return memberOf, nil
	}

	memberOf, err := requestMemberOf(conn, config, result)
	if err != nil {
		return nil, err
	}

	return memberOf, nil
}

// requestMemberOf use this function when POSIX LDAP
// schema does not support memberOf, so it manually search the groups
func requestMemberOf(conn *ldap.Conn, config *LDAPConfig, entry *ldap.Entry) ([]string, error) {
	var memberOf []string

	for _, groupSearchBase := range config.GroupSearchBaseDNs {
		var filterReplace string
		if config.GroupSearchFilterUserAttribute == "" {
			filterReplace = "cn"
		} else {
			filterReplace = getAttribute(
				config.GroupSearchFilterUserAttribute,
				entry,
			)
		}

		filter := strings.Replace(
			config.GroupSearchFilter, "%s",
			ldap.EscapeFilter(filterReplace),
			-1,
		)

		// support old way of reading settings
		groupIDAttribute := config.MemberOfAttribute
		// but prefer dn attribute if default settings are used
		if groupIDAttribute == "" || groupIDAttribute == "memberOf" {
			groupIDAttribute = "dn"
		}

		groupSearchReq := ldap.SearchRequest{
			BaseDN:       groupSearchBase,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: ldap.NeverDerefAliases,
			Attributes:   []string{groupIDAttribute},
			Filter:       filter,
		}

		groupSearchResult, err := conn.Search(&groupSearchReq)
		if err != nil {
			return nil, err
		}

		if len(groupSearchResult.Entries) > 0 {
			for _, group := range groupSearchResult.Entries {

				memberOf = append(
					memberOf,
					getAttribute(groupIDAttribute, group),
				)
			}
			break
		}
	}

	return memberOf, nil
}
