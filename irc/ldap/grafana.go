// Copyright 2014-2018 Grafana Labs
// Released under the Apache 2.0 license

// Modification notice:
// 1. `serverConn` was substituted for `Server` as the type of the server object
// 2. Debug loglines were altered to work with Oragono's logging system

package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

var (
	// ErrInvalidCredentials is returned if username and password do not match
	ErrInvalidCredentials = errors.New("Invalid Username or Password")

	// ErrCouldNotFindUser is returned when username hasn't been found (not username+password)
	ErrCouldNotFindUser = errors.New("Can't find user in LDAP")
)

// shouldAdminBind checks if we should use
// admin username & password for LDAP bind
func (server *serverConn) shouldAdminBind() bool {
	return server.Config.BindPassword != ""
}

// singleBindDN combines the bind with the username
// in order to get the proper path
func (server *serverConn) singleBindDN(username string) string {
	return fmt.Sprintf(server.Config.BindDN, username)
}

// shouldSingleBind checks if we can use "single bind" approach
func (server *serverConn) shouldSingleBind() bool {
	return strings.Contains(server.Config.BindDN, "%s")
}

// Dial dials in the LDAP
// TODO: decrease cyclomatic complexity
func (server *serverConn) Dial() error {
	var err error
	var certPool *x509.CertPool
	if server.Config.RootCACert != "" {
		certPool = x509.NewCertPool()
		for _, caCertFile := range strings.Split(server.Config.RootCACert, " ") {
			pem, err := ioutil.ReadFile(caCertFile)
			if err != nil {
				return err
			}
			if !certPool.AppendCertsFromPEM(pem) {
				return errors.New("Failed to append CA certificate " + caCertFile)
			}
		}
	}
	var clientCert tls.Certificate
	if server.Config.ClientCert != "" && server.Config.ClientKey != "" {
		clientCert, err = tls.LoadX509KeyPair(server.Config.ClientCert, server.Config.ClientKey)
		if err != nil {
			return err
		}
	}
	for _, host := range strings.Split(server.Config.Host, " ") {
		address := fmt.Sprintf("%s:%d", host, server.Config.Port)
		if server.Config.UseSSL {
			tlsCfg := &tls.Config{
				InsecureSkipVerify: server.Config.SkipVerifySSL,
				ServerName:         host,
				RootCAs:            certPool,
			}
			if len(clientCert.Certificate) > 0 {
				tlsCfg.Certificates = append(tlsCfg.Certificates, clientCert)
			}
			if server.Config.StartTLS {
				server.Connection, err = ldap.Dial("tcp", address)
				if err == nil {
					if err = server.Connection.StartTLS(tlsCfg); err == nil {
						return nil
					}
				}
			} else {
				server.Connection, err = ldap.DialTLS("tcp", address, tlsCfg)
			}
		} else {
			server.Connection, err = ldap.Dial("tcp", address)
		}

		if err == nil {
			return nil
		}
	}
	return err
}

// Close closes the LDAP connection
// Dial() sets the connection with the server for this Struct. Therefore, we require a
// call to Dial() before being able to execute this function.
func (server *serverConn) Close() {
	server.Connection.Close()
}

// userBind binds the user with the LDAP server
func (server *serverConn) userBind(path, password string) error {
	err := server.Connection.Bind(path, password)
	if err != nil {
		if ldapErr, ok := err.(*ldap.Error); ok {
			if ldapErr.ResultCode == 49 {
				return ErrInvalidCredentials
			}
		}
		return err
	}

	return nil
}

// users is helper method for the Users()
func (server *serverConn) users(logins []string) (
	[]*ldap.Entry,
	error,
) {
	var result *ldap.SearchResult
	var Config = server.Config
	var err error

	for _, base := range Config.SearchBaseDNs {
		result, err = server.Connection.Search(
			server.getSearchRequest(base, logins),
		)
		if err != nil {
			return nil, err
		}

		if len(result.Entries) > 0 {
			break
		}
	}

	return result.Entries, nil
}

// getSearchRequest returns LDAP search request for users
func (server *serverConn) getSearchRequest(
	base string,
	logins []string,
) *ldap.SearchRequest {
	attributes := []string{}

	inputs := server.Config.Attr
	attributes = appendIfNotEmpty(
		attributes,
		inputs.Username,
		inputs.Surname,
		inputs.Email,
		inputs.Name,
		inputs.MemberOf,

		// In case for the POSIX LDAP schema server
		server.Config.GroupSearchFilterUserAttribute,
	)

	search := ""
	for _, login := range logins {
		query := strings.Replace(
			server.Config.SearchFilter,
			"%s", ldap.EscapeFilter(login),
			-1,
		)

		search = search + query
	}

	filter := fmt.Sprintf("(|%s)", search)

	return &ldap.SearchRequest{
		BaseDN:       base,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Attributes:   attributes,
		Filter:       filter,
	}
}

// requestMemberOf use this function when POSIX LDAP
// schema does not support memberOf, so it manually search the groups
func (server *serverConn) requestMemberOf(entry *ldap.Entry) ([]string, error) {
	var memberOf []string
	var config = server.Config

	for _, groupSearchBase := range config.GroupSearchBaseDNs {
		var filterReplace string
		if config.GroupSearchFilterUserAttribute == "" {
			filterReplace = getAttribute(config.Attr.Username, entry)
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

		server.logger.Debug("ldap", "Searching for groups with filter", filter)

		// support old way of reading settings
		groupIDAttribute := config.Attr.MemberOf
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

		groupSearchResult, err := server.Connection.Search(&groupSearchReq)
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

// getMemberOf finds memberOf property or request it
func (server *serverConn) getMemberOf(result *ldap.Entry) (
	[]string, error,
) {
	if server.Config.GroupSearchFilter == "" {
		memberOf := getArrayAttribute(server.Config.Attr.MemberOf, result)

		return memberOf, nil
	}

	memberOf, err := server.requestMemberOf(result)
	if err != nil {
		return nil, err
	}

	return memberOf, nil
}
