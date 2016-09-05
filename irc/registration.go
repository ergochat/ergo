// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
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

const (
	keyAccountExists      = "account %s exists"
	keyAccountVerified    = "account %s verified"
	keyAccountName        = "account %s name" // stores the 'preferred name' of the account, casemapped appropriately
	keyAccountRegTime     = "account %s registered.time"
	keyAccountCredentials = "account %s credentials"
)

var (
	errAccountCreation = errors.New("Account could not be created")
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

// regHandler parses the REG command.
func regHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	subcommand := strings.ToLower(msg.Params[0])

	if subcommand == "create" {
		return regCreateHandler(server, client, msg)
	} else if subcommand == "verify" {
		client.Notice("Parsing VERIFY")
	} else {
		client.Send(nil, server.nameString, ERR_UNKNOWNERROR, client.nickString, "REG", msg.Params[0], "Unknown subcommand")
	}

	return false
}

// removeFailedRegCreateData removes the data created by REG CREATE if the account creation fails early.
func removeFailedRegCreateData(store buntdb.DB, account string) {
	// error is ignored here, we can't do much about it anyways
	store.Update(func(tx *buntdb.Tx) error {
		tx.Delete(fmt.Sprintf(keyAccountExists, account))
		tx.Delete(fmt.Sprintf(keyAccountRegTime, account))
		tx.Delete(fmt.Sprintf(keyAccountCredentials, account))

		return nil
	})
}

// regCreateHandler parses the REG CREATE command.
func regCreateHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	client.Notice("Parsing CREATE")

	// get and sanitise account name
	account := NewName(msg.Params[1])
	//TODO(dan): probably don't need explicit check for "*" here... until we actually casemap properly as per rfc7700
	if !account.IsNickname() || msg.Params[1] == "*" {
		client.Send(nil, server.nameString, ERR_REG_UNSPECIFIED_ERROR, client.nickString, msg.Params[1], "Account name is not valid")
		return false
	}
	accountString := account.String()

	// check whether account exists
	// do it all in one write tx to prevent races
	err := server.store.Update(func(tx *buntdb.Tx) error {
		accountKey := fmt.Sprintf(keyAccountExists, accountString)

		_, err := tx.Get(accountKey)
		if err != buntdb.ErrNotFound {
			//TODO(dan): if account verified key doesn't exist account is not verified, calc the maximum time without verification and expire and continue if need be
			client.Send(nil, server.nameString, ERR_ACCOUNT_ALREADY_EXISTS, client.nickString, msg.Params[1], "Account already exists")
			return errAccountCreation
		}

		registeredTimeKey := fmt.Sprintf(keyAccountRegTime, accountString)

		tx.Set(accountKey, "1", nil)
		tx.Set(fmt.Sprintf(keyAccountName, accountString), strings.TrimSpace(msg.Params[1]), nil)
		tx.Set(registeredTimeKey, strconv.FormatInt(time.Now().Unix(), 10), nil)
		return nil
	})

	// account could not be created and relevant numerics have been dispatched, abort
	if err != nil {
		if err != errAccountCreation {
			client.Send(nil, server.nameString, ERR_UNKNOWNERROR, client.nickString, "REG", "CREATE", "Could not register")
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
		client.Send(nil, server.nameString, ERR_REG_INVALID_CALLBACK, client.nickString, msg.Params[1], callbackNamespace, "Callback namespace is not supported")
		removeFailedRegCreateData(server.store, accountString)
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
		client.Send(nil, server.nameString, ERR_NEEDMOREPARAMS, client.nickString, msg.Command, "Not enough parameters")
		removeFailedRegCreateData(server.store, accountString)
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
		client.Send(nil, server.nameString, ERR_REG_INVALID_CRED_TYPE, client.nickString, credentialType, callbackNamespace, "You are not using a certificiate")
		removeFailedRegCreateData(server.store, accountString)
		return false
	}

	if !credentialValid {
		client.Send(nil, server.nameString, ERR_REG_INVALID_CRED_TYPE, client.nickString, credentialType, callbackNamespace, "Credential type is not supported")
		removeFailedRegCreateData(server.store, accountString)
		return false
	}

	// store details
	err = server.store.Update(func(tx *buntdb.Tx) error {
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
		tx.Set(keyAccountCredentials, string(credText), nil)

		return nil
	})

	// details could not be stored and relevant numerics have been dispatched, abort
	if err != nil {
		client.Send(nil, server.nameString, ERR_UNKNOWNERROR, client.nickString, "REG", "CREATE", "Could not register")
		log.Println("Could not save registration creds:", err.Error())
		removeFailedRegCreateData(server.store, accountString)
		return false
	}

	// automatically complete registration
	if callbackNamespace == "*" {
		err = server.store.Update(func(tx *buntdb.Tx) error {
			tx.Set(keyAccountVerified, "1", nil)

			// load acct info inside store tx
			account := ClientAccount{
				Name:         strings.TrimSpace(msg.Params[1]),
				RegisteredAt: time.Now(),
				Clients:      []*Client{client},
			}
			//TODO(dan): Consider creating ircd-wide account adding/removing/affecting lock for protecting access to these sorts of variables
			server.accounts[accountString] = &account
			client.account = &account

			client.Send(nil, server.nameString, RPL_REGISTRATION_SUCCESS, client.nickString, accountString, "Account created")
			client.Send(nil, server.nameString, RPL_LOGGEDIN, client.nickString, client.nickMaskString, accountString, fmt.Sprintf("You are now logged in as %s", accountString))
			client.Send(nil, server.nameString, RPL_SASLSUCCESS, client.nickString, "Authentication successful")
			return nil
		})
		if err != nil {
			client.Send(nil, server.nameString, ERR_UNKNOWNERROR, client.nickString, "REG", "CREATE", "Could not register")
			log.Println("Could not save verification confirmation (*):", err.Error())
			removeFailedRegCreateData(server.store, accountString)
			return false
		}

		return false
	}

	// dispatch callback
	client.Notice(fmt.Sprintf("We should dispatch a real callback here to %s:%s", callbackNamespace, callbackValue))

	return false
}
