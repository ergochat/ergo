// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"strings"

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/oragono/oragono/irc/sno"
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
func (server *Server) nickservNoticeHandler(client *Client, message string, rb *ResponseBuffer) {
	// do nothing
}

// nickservPrivmsgHandler handles PRIVMSGs that NickServ receives.
func (server *Server) nickservPrivmsgHandler(client *Client, message string, rb *ResponseBuffer) {
	command, params := extractParam(message)
	command = strings.ToLower(command)

	if command == "help" {
		for _, line := range strings.Split(nickservHelp, "\n") {
			rb.Notice(line)
		}
	} else if command == "register" {
		// get params
		username, passphrase := extractParam(params)

		// fail out if we need to
		if username == "" {
			rb.Notice(client.t("No username supplied"))
			return
		}

		server.nickservRegisterHandler(client, username, passphrase, rb)
	} else if command == "identify" {
		// get params
		username, passphrase := extractParam(params)

		server.nickservIdentifyHandler(client, username, passphrase, rb)
	} else {
		rb.Notice(client.t("Command not recognised. To see the available commands, run /NS HELP"))
	}
}

func (server *Server) nickservRegisterHandler(client *Client, username, passphrase string, rb *ResponseBuffer) {
	certfp := client.certfp
	if passphrase == "" && certfp == "" {
		rb.Notice(client.t("You need to either supply a passphrase or be connected via TLS with a client cert"))
		return
	}

	if !server.AccountConfig().Registration.Enabled {
		rb.Notice(client.t("Account registration has been disabled"))
		return
	}

	if client.LoggedIntoAccount() {
		if server.AccountConfig().Registration.AllowMultiplePerConnection {
			server.accounts.Logout(client)
		} else {
			rb.Notice(client.t("You're already logged into an account"))
			return
		}
	}

	// get and sanitise account name
	account := strings.TrimSpace(username)
	casefoldedAccount, err := CasefoldName(account)
	// probably don't need explicit check for "*" here... but let's do it anyway just to make sure
	if err != nil || username == "*" {
		rb.Notice(client.t("Account name is not valid"))
		return
	}

	// account could not be created and relevant numerics have been dispatched, abort
	if err != nil {
		if err != errAccountCreation {
			rb.Notice(client.t("Account registration failed"))
		}
		return
	}

	err = server.accounts.Register(client, account, "", "", passphrase, client.certfp)
	if err == nil {
		err = server.accounts.Verify(client, casefoldedAccount, "")
	}

	// details could not be stored and relevant numerics have been dispatched, abort
	if err != nil {
		errMsg := "Could not register"
		if err == errCertfpAlreadyExists {
			errMsg = "An account already exists for your certificate fingerprint"
		} else if err == errAccountAlreadyRegistered {
			errMsg = "Account already exists"
		}
		rb.Notice(client.t(errMsg))
		return
	}

	rb.Notice(client.t("Account created"))
	rb.Add(nil, server.name, RPL_LOGGEDIN, client.nick, client.nickMaskString, casefoldedAccount, fmt.Sprintf(client.t("You are now logged in as %s"), casefoldedAccount))
	rb.Add(nil, server.name, RPL_SASLSUCCESS, client.nick, client.t("Authentication successful"))
	server.snomasks.Send(sno.LocalAccounts, fmt.Sprintf(ircfmt.Unescape("Account registered $c[grey][$r%s$c[grey]] by $c[grey][$r%s$c[grey]]"), casefoldedAccount, client.nickMaskString))
}

func (server *Server) nickservIdentifyHandler(client *Client, username, passphrase string, rb *ResponseBuffer) {
	// fail out if we need to
	if !server.AccountConfig().AuthenticationEnabled {
		rb.Notice(client.t("Login has been disabled"))
		return
	}

	// try passphrase
	if username != "" && passphrase != "" {
		// keep it the same as in the ACC CREATE stage
		accountName, err := CasefoldName(username)
		if err != nil {
			rb.Notice(client.t("Could not login with your username/password"))
			return
		}

		err = server.accounts.AuthenticateByPassphrase(client, accountName, passphrase)
		if err == nil {
			rb.Notice(fmt.Sprintf(client.t("You're now logged in as %s"), accountName))
			return
		}
	}

	// try certfp
	if client.certfp != "" {
		err := server.accounts.AuthenticateByCertFP(client)
		if err == nil {
			rb.Notice(fmt.Sprintf(client.t("You're now logged in as %s"), client.AccountName()))
			// TODO more notices?
			return
		}
	}

	rb.Notice(client.t("Could not login with your TLS certificate or supplied username/password"))
}
