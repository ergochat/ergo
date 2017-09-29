// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/oragono/oragono/irc/caps"
	"github.com/oragono/oragono/irc/sno"
	"github.com/tidwall/buntdb"
)

const (
	keyAccountExists      = "account.exists %s"
	keyAccountVerified    = "account.verified %s"
	keyAccountName        = "account.name %s" // stores the 'preferred name' of the account, not casemapped
	keyAccountRegTime     = "account.registered.time %s"
	keyAccountCredentials = "account.credentials %s"
	keyCertToAccount      = "account.creds.certfp %s"
)

var (
	// EnabledSaslMechanisms contains the SASL mechanisms that exist and that we support.
	// This can be moved to some other data structure/place if we need to load/unload mechs later.
	EnabledSaslMechanisms = map[string]func(*Server, *Client, string, []byte) bool{
		"PLAIN":    authPlainHandler,
		"EXTERNAL": authExternalHandler,
	}

	// NoAccount is a placeholder which means that the user is not logged into an account.
	NoAccount = ClientAccount{
		Name: "*", // * is used until actual account name is set
	}

	// generic sasl fail error
	errSaslFail = errors.New("SASL failed")
)

// ClientAccount represents a user account.
type ClientAccount struct {
	// Name of the account.
	Name string
	// RegisteredAt represents the time that the account was registered.
	RegisteredAt time.Time
	// Clients that are currently logged into this account (useful for notifications).
	Clients []*Client
}

// loadAccountCredentials loads an account's credentials from the store.
func loadAccountCredentials(tx *buntdb.Tx, accountKey string) (*AccountCredentials, error) {
	credText, err := tx.Get(fmt.Sprintf(keyAccountCredentials, accountKey))
	if err != nil {
		return nil, err
	}

	var creds AccountCredentials
	err = json.Unmarshal([]byte(credText), &creds)
	if err != nil {
		return nil, err
	}

	return &creds, nil
}

// loadAccount loads an account from the store, note that the account must actually exist.
func loadAccount(server *Server, tx *buntdb.Tx, accountKey string) *ClientAccount {
	name, _ := tx.Get(fmt.Sprintf(keyAccountName, accountKey))
	regTime, _ := tx.Get(fmt.Sprintf(keyAccountRegTime, accountKey))
	regTimeInt, _ := strconv.ParseInt(regTime, 10, 64)
	accountInfo := ClientAccount{
		Name:         name,
		RegisteredAt: time.Unix(regTimeInt, 0),
		Clients:      []*Client{},
	}
	server.accounts[accountKey] = &accountInfo

	return &accountInfo
}

// authenticateHandler parses the AUTHENTICATE command (for SASL authentication).
func authenticateHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// sasl abort
	if !server.accountAuthenticationEnabled || len(msg.Params) == 1 && msg.Params[0] == "*" {
		client.Send(nil, server.name, ERR_SASLABORTED, client.nick, "SASL authentication aborted")
		client.saslInProgress = false
		client.saslMechanism = ""
		client.saslValue = ""
		return false
	}

	// start new sasl session
	if !client.saslInProgress {
		mechanism := strings.ToUpper(msg.Params[0])
		_, mechanismIsEnabled := EnabledSaslMechanisms[mechanism]

		if mechanismIsEnabled {
			client.saslInProgress = true
			client.saslMechanism = mechanism
			client.Send(nil, server.name, "AUTHENTICATE", "+")
		} else {
			client.Send(nil, server.name, ERR_SASLFAIL, client.nick, "SASL authentication failed")
		}

		return false
	}

	// continue existing sasl session
	rawData := msg.Params[0]

	if len(rawData) > 400 {
		client.Send(nil, server.name, ERR_SASLTOOLONG, client.nick, "SASL message too long")
		client.saslInProgress = false
		client.saslMechanism = ""
		client.saslValue = ""
		return false
	} else if len(rawData) == 400 {
		client.saslValue += rawData
		// allow 4 'continuation' lines before rejecting for length
		if len(client.saslValue) > 400*4 {
			client.Send(nil, server.name, ERR_SASLFAIL, client.nick, "SASL authentication failed: Passphrase too long")
			client.saslInProgress = false
			client.saslMechanism = ""
			client.saslValue = ""
			return false
		}
		return false
	}
	if rawData != "+" {
		client.saslValue += rawData
	}

	var data []byte
	var err error
	if client.saslValue != "+" {
		data, err = base64.StdEncoding.DecodeString(client.saslValue)
		if err != nil {
			client.Send(nil, server.name, ERR_SASLFAIL, client.nick, "SASL authentication failed: Invalid b64 encoding")
			client.saslInProgress = false
			client.saslMechanism = ""
			client.saslValue = ""
			return false
		}
	}

	// call actual handler
	handler, handlerExists := EnabledSaslMechanisms[client.saslMechanism]

	// like 100% not required, but it's good to be safe I guess
	if !handlerExists {
		client.Send(nil, server.name, ERR_SASLFAIL, client.nick, "SASL authentication failed")
		client.saslInProgress = false
		client.saslMechanism = ""
		client.saslValue = ""
		return false
	}

	// let the SASL handler do its thing
	exiting := handler(server, client, client.saslMechanism, data)

	// wait 'til SASL is done before emptying the sasl vars
	client.saslInProgress = false
	client.saslMechanism = ""
	client.saslValue = ""

	return exiting
}

// authPlainHandler parses the SASL PLAIN mechanism.
func authPlainHandler(server *Server, client *Client, mechanism string, value []byte) bool {
	splitValue := bytes.Split(value, []byte{'\000'})

	var accountKey, authzid string

	if len(splitValue) == 3 {
		accountKey = string(splitValue[0])
		authzid = string(splitValue[1])

		if accountKey == "" {
			accountKey = authzid
		} else if accountKey != authzid {
			client.Send(nil, server.name, ERR_SASLFAIL, client.nick, "SASL authentication failed: authcid and authzid should be the same")
			return false
		}
	} else {
		client.Send(nil, server.name, ERR_SASLFAIL, client.nick, "SASL authentication failed: Invalid auth blob")
		return false
	}

	// keep it the same as in the REG CREATE stage
	accountKey, err := CasefoldName(accountKey)
	if err != nil {
		client.Send(nil, server.name, ERR_SASLFAIL, client.nick, "SASL authentication failed: Bad account name")
		return false
	}

	// load and check acct data all in one update to prevent races.
	// as noted elsewhere, change to proper locking for Account type later probably
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
		password := string(splitValue[2])
		if len(creds.PassphraseHash) < 1 || len(creds.PassphraseSalt) < 1 || len(password) < 1 {
			return errSaslFail
		}
		err = server.passwords.CompareHashAndPassword(creds.PassphraseHash, creds.PassphraseSalt, password)

		// succeeded, load account info if necessary
		account, exists := server.accounts[accountKey]
		if !exists {
			account = loadAccount(server, tx, accountKey)
		}

		client.LoginToAccount(account)

		return err
	})

	if err != nil {
		client.Send(nil, server.name, ERR_SASLFAIL, client.nick, "SASL authentication failed")
		return false
	}

	client.successfulSaslAuth()
	return false
}

// LoginToAccount logs the client into the given account.
func (client *Client) LoginToAccount(account *ClientAccount) {
	if client.account == account {
		// already logged into this acct, no changing necessary
		return
	} else if client.LoggedIntoAccount() {
		// logout of existing acct
		var newClientAccounts []*Client
		for _, c := range account.Clients {
			if c != client {
				newClientAccounts = append(newClientAccounts, c)
			}
		}
		account.Clients = newClientAccounts
	}

	account.Clients = append(account.Clients, client)
	client.account = account
	client.server.snomasks.Send(sno.LocalAccounts, fmt.Sprintf(ircfmt.Unescape("Client $c[grey][$r%s$c[grey]] logged into account $c[grey][$r%s$c[grey]]"), client.nickMaskString, account.Name))

	//TODO(dan): This should output the AccountNotify message instead of the sasl accepted function below.
}

// LogoutOfAccount logs the client out of their current account.
func (client *Client) LogoutOfAccount() {
	account := client.account
	if account == nil {
		// already logged out
		return
	}

	// logout of existing acct
	var newClientAccounts []*Client
	for _, c := range account.Clients {
		if c != client {
			newClientAccounts = append(newClientAccounts, c)
		}
	}
	account.Clients = newClientAccounts

	client.account = nil

	// dispatch account-notify
	for friend := range client.Friends(caps.AccountNotify) {
		friend.Send(nil, client.nickMaskString, "ACCOUNT", "*")
	}
}

// authExternalHandler parses the SASL EXTERNAL mechanism.
func authExternalHandler(server *Server, client *Client, mechanism string, value []byte) bool {
	if client.certfp == "" {
		client.Send(nil, server.name, ERR_SASLFAIL, client.nick, "SASL authentication failed, you are not connecting with a certificate")
		return false
	}

	err := server.store.Update(func(tx *buntdb.Tx) error {
		// certfp lookup key
		accountKey, err := tx.Get(fmt.Sprintf(keyCertToAccount, client.certfp))
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

		return nil
	})

	if err != nil {
		client.Send(nil, server.name, ERR_SASLFAIL, client.nick, "SASL authentication failed")
		return false
	}

	client.successfulSaslAuth()
	return false
}

// successfulSaslAuth means that a SASL auth attempt completed successfully, and is used to dispatch messages.
func (client *Client) successfulSaslAuth() {
	client.Send(nil, client.server.name, RPL_LOGGEDIN, client.nick, client.nickMaskString, client.account.Name, fmt.Sprintf("You are now logged in as %s", client.account.Name))
	client.Send(nil, client.server.name, RPL_SASLSUCCESS, client.nick, "SASL authentication successful")

	// dispatch account-notify
	for friend := range client.Friends(caps.AccountNotify) {
		friend.Send(nil, client.nickMaskString, "ACCOUNT", client.account.Name)
	}
}
