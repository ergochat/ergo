// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/DanielOaks/girc-go/ircmsg"
	"github.com/tidwall/buntdb"
)

var (
	errAccountCreation = errors.New("Account could not be created")
)

// AccountRegistration manages the registration of accounts.
type AccountRegistration struct {
	Enabled              bool
	EnabledCallbackTypes []string
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
			accountReg.EnabledCallbackTypes = append(accountReg.EnabledCallbackTypes, name)
		}
	}
	return accountReg
}

// regHandler parses the REG command.
func regHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	subcommand := strings.ToLower(msg.Params[0])

	if subcommand == "create" {
		client.Notice("Parsing CREATE")

		// get and sanitise account name
		account := NewName(msg.Params[1])
		if !account.IsNickname() || msg.Params[1] == "*" {
			client.Send(nil, server.nameString, ERR_REG_UNSPECIFIED_ERROR, client.nickString, msg.Params[1], "Account name is not valid")
			return false
		}
		accountString := account.String()

		// check whether account exists
		// do it all in one write tx to prevent races
		err := server.store.Update(func(tx *buntdb.Tx) error {
			accountKey := fmt.Sprintf("account %s exists", accountString)

			_, err := tx.Get(accountKey)
			if err != buntdb.ErrNotFound {
				//TODO(dan): if account verified key doesn't exist account is not verified, calc the maximum time without verification and expire and continue if need be
				client.Send(nil, server.nameString, ERR_ACCOUNT_ALREADY_EXISTS, client.nickString, msg.Params[1], "Account already exists")
				return errAccountCreation
			}

			registeredTimeKey := fmt.Sprintf("account %s registered.time", accountString)

			tx.Set(accountKey, "1", nil)
			tx.Set(registeredTimeKey, strconv.FormatInt(time.Now().Unix(), 10), nil)
			return nil
		})

		// account could not be created and relevant numerics have been dispatched, abort
		if err != nil {
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
			callbackNamespace = server.accountRegistration.EnabledCallbackTypes[0]
			callbackValue = callback
		}

		// ensure the callback namespace is valid
		// need to search callback list, maybe look at using a map later?
		var callbackValid bool
		for _, name := range server.accountRegistration.EnabledCallbackTypes {
			if callbackNamespace == name {
				callbackValid = true
			}
		}

		if !callbackValid {
			client.Send(nil, server.nameString, ERR_REG_INVALID_CALLBACK, client.nickString, msg.Params[1], callbackNamespace, "Callback namespace is not supported")
			//TODO(dan): close out failed account reg (remove values from db)
			return false
		}

		// ensure the credential type is valid
		var credentialType, credentialValue string

		if len(msg.Params) > 4 {
			credentialType = strings.ToLower(msg.Params[3])
			credentialValue = msg.Params[4]
		} else if len(msg.Params) == 4 {
			credentialType = "passphrase" // default from the spec
			credentialValue = msg.Params[3]
		} else {
			client.Send(nil, server.nameString, ERR_NEEDMOREPARAMS, client.nickString, msg.Command, "Not enough parameters")
			//TODO(dan): close out failed account reg (remove values from db)
			return false
		}

		// dispatch callback
		if callbackNamespace != "*" {
			client.Notice("Account creation was successful!")
			//TODO(dan): close out failed account reg (remove values from db)
			return false
		}

		client.Notice(fmt.Sprintf("We should dispatch an actual callback here to %s:%s", callbackNamespace, callbackValue))
		client.Notice(fmt.Sprintf("Primary account credential is with %s:%s", credentialType, credentialValue))

	} else if subcommand == "verify" {
		client.Notice("Parsing VERIFY")
	} else {
		client.Send(nil, server.nameString, ERR_UNKNOWNERROR, client.nickString, "REG", msg.Params[0], "Unknown subcommand")
	}

	return false
}
