// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/oragono/oragono/irc/passwd"
	"github.com/oragono/oragono/irc/sno"
	"github.com/tidwall/buntdb"
)

const nickservHelp = `NickServ lets you register and log into a user account.

To register an account:
	/NS REGISTER username [password]
Leave out [password] if you're registering using your client certificate fingerprint.

To login to an account:
	/NS IDENTIFY [username password]
Leave out [username password] to use your client certificate fingerprint. Otherwise,
the given username and password will be used.`

// extractParam extracts a parameter from the given string, returning the param and the rest of the string.
func extractParam(line string) (string, string) {
	rawParams := strings.SplitN(strings.TrimSpace(line), " ", 2)
	param0 := rawParams[0]
	var param1 string
	if 1 < len(rawParams) {
		param1 = strings.TrimSpace(rawParams[1])
	}
	return param0, param1
}

// nickservNoticeHandler handles NOTICEs that NickServ receives.
func (server *Server) nickservNoticeHandler(client *Client, message string) {
	// do nothing
}

// nickservPrivmsgHandler handles PRIVMSGs that NickServ receives.
func (server *Server) nickservPrivmsgHandler(client *Client, message string) {
	command, params := extractParam(message)
	command = strings.ToLower(command)

	if command == "help" {
		for _, line := range strings.Split(nickservHelp, "\n") {
			client.Notice(line)
		}
	} else if command == "register" {
		// get params
		username, passphrase := extractParam(params)

		// fail out if we need to
		if username == "" {
			client.Notice(client.t("No username supplied"))
			return
		}

		certfp := client.certfp
		if passphrase == "" && certfp == "" {
			client.Notice(client.t("You need to either supply a passphrase or be connected via TLS with a client cert"))
			return
		}

		if !server.accountRegistration.Enabled {
			client.Notice(client.t("Account registration has been disabled"))
			return
		}

		if client.LoggedIntoAccount() {
			if server.accountRegistration.AllowMultiplePerConnection {
				client.LogoutOfAccount()
			} else {
				client.Notice(client.t("You're already logged into an account"))
				return
			}
		}

		// get and sanitise account name
		account := strings.TrimSpace(username)
		casefoldedAccount, err := CasefoldName(account)
		// probably don't need explicit check for "*" here... but let's do it anyway just to make sure
		if err != nil || username == "*" {
			client.Notice(client.t("Account name is not valid"))
			return
		}

		// check whether account exists
		// do it all in one write tx to prevent races
		err = server.store.Update(func(tx *buntdb.Tx) error {
			accountKey := fmt.Sprintf(keyAccountExists, casefoldedAccount)

			_, err := tx.Get(accountKey)
			if err != buntdb.ErrNotFound {
				//TODO(dan): if account verified key doesn't exist account is not verified, calc the maximum time without verification and expire and continue if need be
				client.Notice(client.t("Account already exists"))
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
				client.Notice(client.t("Account registration failed"))
			}
			return
		}

		// store details
		err = server.store.Update(func(tx *buntdb.Tx) error {
			// certfp special lookup key
			if passphrase == "" {
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
			creds.PassphraseSalt, err = passwd.NewSalt()
			if err != nil {
				return fmt.Errorf("Could not create passphrase salt: %s", err.Error())
			}

			if passphrase == "" {
				creds.Certificate = client.certfp
			} else {
				creds.PassphraseHash, err = server.passwords.GenerateFromPassword(creds.PassphraseSalt, passphrase)
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
			client.Notice(errMsg)
			removeFailedAccRegisterData(server.store, casefoldedAccount)
			return
		}

		err = server.store.Update(func(tx *buntdb.Tx) error {
			tx.Set(fmt.Sprintf(keyAccountVerified, casefoldedAccount), "1", nil)

			// load acct info inside store tx
			account := ClientAccount{
				Name:         username,
				RegisteredAt: time.Now(),
				Clients:      []*Client{client},
			}
			//TODO(dan): Consider creating ircd-wide account adding/removing/affecting lock for protecting access to these sorts of variables
			server.accounts[casefoldedAccount] = &account
			client.account = &account

			client.Notice(client.t("Account created"))
			client.Send(nil, server.name, RPL_LOGGEDIN, client.nick, client.nickMaskString, account.Name, fmt.Sprintf(client.t("You are now logged in as %s"), account.Name))
			client.Send(nil, server.name, RPL_SASLSUCCESS, client.nick, client.t("Authentication successful"))
			server.snomasks.Send(sno.LocalAccounts, fmt.Sprintf(ircfmt.Unescape("Account registered $c[grey][$r%s$c[grey]] by $c[grey][$r%s$c[grey]]"), account.Name, client.nickMaskString))
			return nil
		})
		if err != nil {
			client.Notice(client.t("Account registration failed"))
			removeFailedAccRegisterData(server.store, casefoldedAccount)
			return
		}

	} else if command == "identify" {
		// fail out if we need to
		if !server.accountAuthenticationEnabled {
			client.Notice(client.t("Login has been disabled"))
			return
		}

		// try passphrase
		username, passphrase := extractParam(params)
		if username != "" && passphrase != "" {
			// keep it the same as in the ACC CREATE stage
			accountKey, err := CasefoldName(username)
			if err != nil {
				client.Notice(client.t("Could not login with your username/password"))
				return
			}

			// load and check acct data all in one update to prevent races.
			// as noted elsewhere, change to proper locking for Account type later probably
			var accountName string
			err = server.store.Update(func(tx *buntdb.Tx) error {
				// confirm account is verified
				_, err = tx.Get(fmt.Sprintf(keyAccountVerified, accountKey))
				if err != nil {
					return errSaslFail
				}

				creds, err := loadAccountCredentials(tx, accountKey)
				if err != nil {
					return err
				}

				// ensure creds are valid
				if len(creds.PassphraseHash) < 1 || len(creds.PassphraseSalt) < 1 || len(passphrase) < 1 {
					return errSaslFail
				}
				err = server.passwords.CompareHashAndPassword(creds.PassphraseHash, creds.PassphraseSalt, passphrase)

				// succeeded, load account info if necessary
				account, exists := server.accounts[accountKey]
				if !exists {
					account = loadAccount(server, tx, accountKey)
				}

				client.LoginToAccount(account)
				accountName = account.Name

				return err
			})

			if err == nil {
				client.Notice(fmt.Sprintf(client.t("You're now logged in as %s"), accountName))
				return
			}
		}

		// try certfp
		certfp := client.certfp
		if certfp != "" {
			var accountName string
			err := server.store.Update(func(tx *buntdb.Tx) error {
				// certfp lookup key
				accountKey, err := tx.Get(fmt.Sprintf(keyCertToAccount, certfp))
				if err != nil {
					return errSaslFail
				}

				// confirm account exists
				_, err = tx.Get(fmt.Sprintf(keyAccountExists, accountKey))
				if err != nil {
					return errSaslFail
				}

				// confirm account is verified
				_, err = tx.Get(fmt.Sprintf(keyAccountVerified, accountKey))
				if err != nil {
					return errSaslFail
				}

				// confirm the certfp in that account's credentials
				creds, err := loadAccountCredentials(tx, accountKey)
				if err != nil || creds.Certificate != client.certfp {
					return errSaslFail
				}

				// succeeded, load account info if necessary
				account, exists := server.accounts[accountKey]
				if !exists {
					account = loadAccount(server, tx, accountKey)
				}

				client.LoginToAccount(account)
				accountName = account.Name

				return nil
			})

			if err == nil {
				client.Notice(fmt.Sprintf(client.t("You're now logged in as %s"), accountName))
				return
			}
		}

		client.Notice(client.t("Could not login with your TLS certificate or supplied username/password"))
	} else {
		client.Notice(client.t("Command not recognised. To see the available commands, run /NS HELP"))
	}
}
