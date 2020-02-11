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
	"errors"
	"fmt"

	ldap "github.com/go-ldap/ldap/v3"

	"github.com/oragono/oragono/irc/logger"
)

var (
	ErrUserNotInRequiredGroup = errors.New("User is not a member of any required groups")
)

// equivalent of Grafana's `Server`, but unexported
type serverConn struct {
	Config     *ServerConfig
	Connection *ldap.Conn
	log        *logger.Manager
}

func CheckLDAPPassphrase(config ServerConfig, accountName, passphrase string, log *logger.Manager) (err error) {
	defer func() {
		if err != nil {
			log.Debug("ldap", "failed passphrase check", err.Error())
		}
	}()

	server := serverConn{
		Config: &config,
		log:    log,
	}

	err = server.Dial()
	if err != nil {
		return
	}
	defer server.Close()

	server.Connection.SetTimeout(config.Timeout)

	passphraseChecked := false

	if server.shouldSingleBind() {
		log.Debug("ldap", "attempting single bind to", accountName)
		err = server.userBind(server.singleBindDN(accountName), passphrase)
		passphraseChecked = (err == nil)
	} else if server.shouldAdminBind() {
		log.Debug("ldap", "attempting admin bind to", config.BindDN)
		err = server.userBind(config.BindDN, config.BindPassword)
	} else {
		log.Debug("ldap", "attempting unauthenticated bind")
		err = server.Connection.UnauthenticatedBind(config.BindDN)
	}

	if err != nil {
		return
	}

	if passphraseChecked && len(config.RequireGroups) == 0 {
		return nil
	}

	users, err := server.users([]string{accountName})
	if err != nil {
		log.Debug("ldap", "failed user lookup")
		return err
	}

	if len(users) == 0 {
		return ErrCouldNotFindUser
	}

	user := users[0]

	log.Debug("ldap", "looked up user", user.DN)

	err = server.validateGroupMembership(user)
	if err != nil {
		return err
	}

	if !passphraseChecked {
		log.Debug("ldap", "rebinding", user.DN)
		err = server.userBind(user.DN, passphrase)
	}

	return err
}

func (server *serverConn) validateGroupMembership(user *ldap.Entry) (err error) {
	if len(server.Config.RequireGroups) == 0 {
		return
	}

	var memberOf []string
	memberOf, err = server.getMemberOf(user)
	if err != nil {
		server.log.Debug("ldap", "could not retrieve group memberships", err.Error())
		return
	}
	server.log.Debug("ldap", fmt.Sprintf("found group memberships: %v", memberOf))
	foundGroup := false
	for _, inGroup := range memberOf {
		for _, acceptableGroup := range server.Config.RequireGroups {
			if inGroup == acceptableGroup {
				foundGroup = true
				break
			}
		}
		if foundGroup {
			break
		}
	}
	if foundGroup {
		return nil
	} else {
		return ErrUserNotInRequiredGroup
	}
}
