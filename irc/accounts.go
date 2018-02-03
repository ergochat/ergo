// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/goshuirc/irc-go/ircfmt"
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

// successfulSaslAuth means that a SASL auth attempt completed successfully, and is used to dispatch messages.
func (client *Client) successfulSaslAuth() {
	client.Send(nil, client.server.name, RPL_LOGGEDIN, client.nick, client.nickMaskString, client.account.Name, fmt.Sprintf("You are now logged in as %s", client.account.Name))
	client.Send(nil, client.server.name, RPL_SASLSUCCESS, client.nick, client.t("SASL authentication successful"))

	// dispatch account-notify
	for friend := range client.Friends(caps.AccountNotify) {
		friend.Send(nil, client.nickMaskString, "ACCOUNT", client.account.Name)
	}
}
