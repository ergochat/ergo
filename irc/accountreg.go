// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/DanielOaks/girc-go/ircmsg"
	"github.com/tidwall/buntdb"
)

var (
	errAccountCreation     = errors.New("Account could not be created")
	errCertfpAlreadyExists = errors.New("An account already exists with your certificate")
)

// AccountRegistration manages the registration of accounts.
type AccountRegistration struct {
	Enabled                bool
	EnabledCallbacks       []string
	EnabledCredentialTypes []string
}

// AccountCredentials stores the various methods for verifying accounts.
type AccountCredentials struct {
	PassphraseSalt []byte
	PassphraseHash []byte
	Certificate    string // fingerprint
}

// NewAccountRegistration returns a new AccountRegistration, configured correctly.
func NewAccountRegistration(config AccountRegistrationConfig) (accountReg AccountRegistration) {
	if config.Enabled {
		accountReg.Enabled = true
		for _, name := range config.EnabledCallbacks {
			// we store "none" as "*" internally
			if name == "none" {
				name = "*"
			}
			accountReg.EnabledCallbacks = append(accountReg.EnabledCallbacks, name)
		}
		// no need to make this configurable, right now at least
		accountReg.EnabledCredentialTypes = []string{
			"passphrase",
			"certfp",
		}
	}
	return accountReg
}

// accHandler parses the ACC command.
func accHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	subcommand := strings.ToLower(msg.Params[0])

	if subcommand == "register" {
		return accRegisterHandler(server, client, msg)
	} else if subcommand == "verify" {
		client.Notice("VERIFY is not yet implemented")
	} else {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, "ACC", msg.Params[0], "Unknown subcommand")
	}

	return false
}

// removeFailedAccRegisterData removes the data created by ACC REGISTER if the account creation fails early.
func removeFailedAccRegisterData(store *buntdb.DB, account string) {
	// error is ignored here, we can't do much about it anyways
	store.Update(func(tx *buntdb.Tx) error {
		tx.Delete(fmt.Sprintf(keyAccountExists, account))
		tx.Delete(fmt.Sprintf(keyAccountRegTime, account))
		tx.Delete(fmt.Sprintf(keyAccountCredentials, account))

		return nil
	})
}

// accRegisterHandler parses the ACC REGISTER command.
func accRegisterHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// make sure reg is enabled
	if !server.accountRegistration.Enabled {
		client.Send(nil, server.name, ERR_REG_UNSPECIFIED_ERROR, client.nick, "*", "Account registration is disabled")
		return false
	}

	// get and sanitise account name
	account := strings.TrimSpace(msg.Params[1])
	casefoldedAccount, err := CasefoldName(account)
	// probably don't need explicit check for "*" here... but let's do it anyway just to make sure
	if err != nil || msg.Params[1] == "*" {
		client.Send(nil, server.name, ERR_REG_UNSPECIFIED_ERROR, client.nick, account, "Account name is not valid")
		return false
	}

	// check whether account exists
	// do it all in one write tx to prevent races
	err = server.store.Update(func(tx *buntdb.Tx) error {
		accountKey := fmt.Sprintf(keyAccountExists, casefoldedAccount)

		_, err := tx.Get(accountKey)
		if err != buntdb.ErrNotFound {
			//TODO(dan): if account verified key doesn't exist account is not verified, calc the maximum time without verification and expire and continue if need be
			client.Send(nil, server.name, ERR_ACCOUNT_ALREADY_EXISTS, client.nick, account, "Account already exists")
			return errAccountCreation
		}

		registeredTimeKey := fmt.Sprintf(keyAccountRegTime, casefoldedAccount)

		tx.Set(accountKey, "1", nil)
		tx.Set(fmt.Sprintf(keyAccountName, casefoldedAccount), account, nil)
		tx.Set(registeredTimeKey, strconv.FormatInt(time.Now().Unix(), 10), nil)
		return nil
	})

	// account could not be created and relevant numerics have been dispatched, abort
	if err != nil {
		if err != errAccountCreation {
			client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, "ACC", "REGISTER", "Could not register")
			log.Println("Could not save registration initial data:", err.Error())
		}
		return false
	}

	// account didn't already exist, continue with account creation and dispatching verification (if required)
	callback := strings.ToLower(msg.Params[2])
	var callbackNamespace, callbackValue string

	if callback == "*" {
		callbackNamespace = "*"
	} else if strings.Contains(callback, ":") {
		callbackValues := strings.SplitN(callback, ":", 2)
		callbackNamespace, callbackValue = callbackValues[0], callbackValues[1]
	} else {
		callbackNamespace = server.accountRegistration.EnabledCallbacks[0]
		callbackValue = callback
	}

	// ensure the callback namespace is valid
	// need to search callback list, maybe look at using a map later?
	var callbackValid bool
	for _, name := range server.accountRegistration.EnabledCallbacks {
		if callbackNamespace == name {
			callbackValid = true
		}
	}

	if !callbackValid {
		client.Send(nil, server.name, ERR_REG_INVALID_CALLBACK, client.nick, account, callbackNamespace, "Callback namespace is not supported")
		removeFailedAccRegisterData(server.store, casefoldedAccount)
		return false
	}

	// get credential type/value
	var credentialType, credentialValue string

	if len(msg.Params) > 4 {
		credentialType = strings.ToLower(msg.Params[3])
		credentialValue = msg.Params[4]
	} else if len(msg.Params) == 4 {
		credentialType = "passphrase" // default from the spec
		credentialValue = msg.Params[3]
	} else {
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, msg.Command, "Not enough parameters")
		removeFailedAccRegisterData(server.store, casefoldedAccount)
		return false
	}

	// ensure the credential type is valid
	var credentialValid bool
	for _, name := range server.accountRegistration.EnabledCredentialTypes {
		if credentialType == name {
			credentialValid = true
		}
	}
	if credentialType == "certfp" && client.certfp == "" {
		client.Send(nil, server.name, ERR_REG_INVALID_CRED_TYPE, client.nick, credentialType, callbackNamespace, "You are not using a certificiate")
		removeFailedAccRegisterData(server.store, casefoldedAccount)
		return false
	}

	if !credentialValid {
		client.Send(nil, server.name, ERR_REG_INVALID_CRED_TYPE, client.nick, credentialType, callbackNamespace, "Credential type is not supported")
		removeFailedAccRegisterData(server.store, casefoldedAccount)
		return false
	}

	// store details
	err = server.store.Update(func(tx *buntdb.Tx) error {
		// certfp special lookup key
		if credentialType == "certfp" {
			assembledKeyCertToAccount := fmt.Sprintf(keyCertToAccount, client.certfp)

			// make sure certfp doesn't already exist because that'd be silly
			_, err := tx.Get(assembledKeyCertToAccount)
			if err != buntdb.ErrNotFound {
				return errCertfpAlreadyExists
			}

			tx.Set(assembledKeyCertToAccount, casefoldedAccount, nil)
		}

		// make creds
		var creds AccountCredentials

		// always set passphrase salt
		creds.PassphraseSalt, err = NewSalt()
		if err != nil {
			return fmt.Errorf("Could not create passphrase salt: %s", err.Error())
		}

		if credentialType == "certfp" {
			creds.Certificate = client.certfp
		} else if credentialType == "passphrase" {
			creds.PassphraseHash, err = server.passwords.GenerateFromPassword(creds.PassphraseSalt, credentialValue)
			if err != nil {
				return fmt.Errorf("Could not hash password: %s", err)
			}
		}
		credText, err := json.Marshal(creds)
		if err != nil {
			return fmt.Errorf("Could not marshal creds: %s", err)
		}
		tx.Set(fmt.Sprintf(keyAccountCredentials, account), string(credText), nil)

		return nil
	})

	// details could not be stored and relevant numerics have been dispatched, abort
	if err != nil {
		errMsg := "Could not register"
		if err == errCertfpAlreadyExists {
			errMsg = "An account already exists for your certificate fingerprint"
		}
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, "ACC", "REGISTER", errMsg)
		log.Println("Could not save registration creds:", err.Error())
		removeFailedAccRegisterData(server.store, casefoldedAccount)
		return false
	}

	// automatically complete registration
	if callbackNamespace == "*" {
		err = server.store.Update(func(tx *buntdb.Tx) error {
			tx.Set(fmt.Sprintf(keyAccountVerified, casefoldedAccount), "1", nil)

			// load acct info inside store tx
			account := ClientAccount{
				Name:         strings.TrimSpace(msg.Params[1]),
				RegisteredAt: time.Now(),
				Clients:      []*Client{client},
			}
			//TODO(dan): Consider creating ircd-wide account adding/removing/affecting lock for protecting access to these sorts of variables
			server.accounts[casefoldedAccount] = &account
			client.account = &account

			client.Send(nil, server.name, RPL_REGISTRATION_SUCCESS, client.nick, account.Name, "Account created")
			client.Send(nil, server.name, RPL_LOGGEDIN, client.nick, client.nickMaskString, account.Name, fmt.Sprintf("You are now logged in as %s", account.Name))
			client.Send(nil, server.name, RPL_SASLSUCCESS, client.nick, "Authentication successful")
			return nil
		})
		if err != nil {
			client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, "ACC", "REGISTER", "Could not register")
			log.Println("Could not save verification confirmation (*):", err.Error())
			removeFailedAccRegisterData(server.store, casefoldedAccount)
			return false
		}

		return false
	}

	// dispatch callback
	client.Notice(fmt.Sprintf("We should dispatch a real callback here to %s:%s", callbackNamespace, callbackValue))

	return false
}
