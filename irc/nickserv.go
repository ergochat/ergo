// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"

	"github.com/goshuirc/irc-go/ircfmt"
)

// "enabled" callbacks for specific nickserv commands
func servCmdRequiresAccreg(config *Config) bool {
	return config.Accounts.Registration.Enabled
}

func servCmdRequiresAuthEnabled(config *Config) bool {
	return config.Accounts.AuthenticationEnabled
}

func servCmdRequiresNickRes(config *Config) bool {
	return config.Accounts.AuthenticationEnabled && config.Accounts.NickReservation.Enabled
}

func nsEnforceEnabled(config *Config) bool {
	return servCmdRequiresNickRes(config) && config.Accounts.NickReservation.AllowCustomEnforcement
}

var (
	// ZNC's nickserv module will not detect this unless it is:
	// 1. sent with prefix `nickserv`
	// 2. contains the string "identify"
	// 3. contains at least one of several other magic strings ("msg" works)
	nsTimeoutNotice = `This nickname is reserved. Please login within %v (using $b/msg NickServ IDENTIFY <password>$b or SASL)`
)

const nickservHelp = `NickServ lets you register and login to an account.

To see in-depth help for a specific NickServ command, try:
    $b/NS HELP <command>$b

Here are the commands you can use:
%s`

var (
	nickservCommands = map[string]*serviceCommand{
		"drop": {
			handler: nsDropHandler,
			help: `Syntax: $bDROP [nickname]$b

DROP de-links the given (or your current) nickname from your user account.`,
			helpShort:    `$bDROP$b de-links your current (or the given) nickname from your user account.`,
			enabled:      servCmdRequiresNickRes,
			authRequired: true,
		},
		"enforce": {
			handler: nsEnforceHandler,
			help: `Syntax: $bENFORCE [method]$b

ENFORCE lets you specify a custom enforcement mechanism for your registered
nicknames. Your options are:
1. 'none'    [no enforcement, overriding the server default]
2. 'timeout' [anyone using the nick must authenticate before a deadline,
              or else they will be renamed]
3. 'strict'  [you must already be authenticated to use the nick]
4. 'default' [use the server default]
With no arguments, queries your current enforcement status.`,
			helpShort:    `$bENFORCE$b lets you change how your nicknames are reserved.`,
			authRequired: true,
			enabled:      nsEnforceEnabled,
		},
		"ghost": {
			handler: nsGhostHandler,
			help: `Syntax: $bGHOST <nickname>$b

GHOST disconnects the given user from the network if they're logged in with the
same user account, letting you reclaim your nickname.`,
			helpShort:    `$bGHOST$b reclaims your nickname.`,
			authRequired: true,
			minParams:    1,
		},
		"group": {
			handler: nsGroupHandler,
			help: `Syntax: $bGROUP$b

GROUP links your current nickname with your logged-in account, preventing other
users from changing to it (or forcing them to rename).`,
			helpShort:    `$bGROUP$b links your current nickname to your user account.`,
			enabled:      servCmdRequiresNickRes,
			authRequired: true,
		},
		"identify": {
			handler: nsIdentifyHandler,
			help: `Syntax: $bIDENTIFY <username> [password]$b

IDENTIFY lets you login to the given username using either password auth, or
certfp (your client certificate) if a password is not given.`,
			helpShort: `$bIDENTIFY$b lets you login to your account.`,
			minParams: 1,
		},
		"info": {
			handler: nsInfoHandler,
			help: `Syntax: $bINFO [username]$b

INFO gives you information about the given (or your own) user account.`,
			helpShort: `$bINFO$b gives you information on a user account.`,
		},
		"register": {
			handler: nsRegisterHandler,
			// TODO: "email" is an oversimplification here; it's actually any callback, e.g.,
			// person@example.com, mailto:person@example.com, tel:16505551234.
			help: `Syntax: $bREGISTER <username> <email> [password]$b

REGISTER lets you register a user account. If the server allows anonymous
registration, you can send an asterisk (*) as the email address.

If the password is left out, your account will be registered to your TLS client
certificate (and you will need to use that certificate to login in future).`,
			helpShort: `$bREGISTER$b lets you register a user account.`,
			enabled:   servCmdRequiresAccreg,
			minParams: 2,
		},
		"sadrop": {
			handler: nsDropHandler,
			help: `Syntax: $bSADROP <nickname>$b

SADROP forcibly de-links the given nickname from the attached user account.`,
			helpShort: `$bSADROP$b forcibly de-links the given nickname from its user account.`,
			capabs:    []string{"accreg"},
			enabled:   servCmdRequiresNickRes,
			minParams: 1,
		},
		"saregister": {
			handler: nsSaregisterHandler,
			help: `Syntax: $bSAREGISTER <username> <password>$b

SAREGISTER registers an account on someone else's behalf.
This is for use in configurations that require SASL for all connections;
an administrator can set use this command to set up user accounts.`,
			helpShort: `$bSAREGISTER$b registers an account on someone else's behalf.`,
			enabled:   servCmdRequiresAuthEnabled,
			capabs:    []string{"accreg"},
			minParams: 2,
		},
		"unregister": {
			handler: nsUnregisterHandler,
			help: `Syntax: $bUNREGISTER <username> [code]$b

UNREGISTER lets you delete your user account (or someone else's, if you're an
IRC operator with the correct permissions). To prevent accidental
unregistrations, a verification code is required; invoking the command without
a code will display the necessary code.`,
			helpShort: `$bUNREGISTER$b lets you delete your user account.`,
			enabled:   servCmdRequiresAuthEnabled,
			minParams: 1,
		},
		"verify": {
			handler: nsVerifyHandler,
			help: `Syntax: $bVERIFY <username> <code>$b

VERIFY lets you complete an account registration, if the server requires email
or other verification.`,
			helpShort: `$bVERIFY$b lets you complete account registration.`,
			enabled:   servCmdRequiresAccreg,
			minParams: 2,
		},
		"passwd": {
			handler: nsPasswdHandler,
			help: `Syntax: $bPASSWD <current> <new> <new_again>$b
Or:     $bPASSWD <username> <new>$b

PASSWD lets you change your account password. You must supply your current
password and confirm the new one by typing it twice. If you're an IRC operator
with the correct permissions, you can use PASSWD to reset someone else's
password by supplying their username and then the desired password.`,
			helpShort: `$bPASSWD$b lets you change your password.`,
			enabled:   servCmdRequiresAuthEnabled,
			minParams: 2,
		},
	}
)

// nsNotice sends the client a notice from NickServ
func nsNotice(rb *ResponseBuffer, text string) {
	rb.Add(nil, "NickServ", "NOTICE", rb.target.Nick(), text)
}

func nsDropHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	sadrop := command == "sadrop"
	var nick string
	if len(params) > 0 {
		nick = params[0]
	} else {
		nick = client.NickCasefolded()
	}

	err := server.accounts.SetNickReserved(client, nick, sadrop, false)
	if err == nil {
		nsNotice(rb, fmt.Sprintf(client.t("Successfully ungrouped nick %s with your account"), nick))
	} else if err == errAccountNotLoggedIn {
		nsNotice(rb, client.t("You're not logged into an account"))
	} else if err == errAccountCantDropPrimaryNick {
		nsNotice(rb, client.t("You can't ungroup your primary nickname (try unregistering your account instead)"))
	} else {
		nsNotice(rb, client.t("Could not ungroup nick"))
	}
}

func nsGhostHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	nick := params[0]

	ghost := server.clients.Get(nick)
	if ghost == nil {
		nsNotice(rb, client.t("No such nick"))
		return
	} else if ghost == client {
		nsNotice(rb, client.t("You can't GHOST yourself (try /QUIT instead)"))
		return
	}

	authorized := false
	account := client.Account()
	if account != "" {
		// the user must either own the nick, or the target client
		authorized = (server.accounts.NickToAccount(nick) == account) || (ghost.Account() == account)
	}
	if !authorized {
		nsNotice(rb, client.t("You don't own that nick"))
		return
	}

	ghost.Quit(fmt.Sprintf(ghost.t("GHOSTed by %s"), client.Nick()))
	ghost.destroy(false)
}

func nsGroupHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	nick := client.Nick()
	err := server.accounts.SetNickReserved(client, nick, false, true)
	if err == nil {
		nsNotice(rb, fmt.Sprintf(client.t("Successfully grouped nick %s with your account"), nick))
	} else if err == errAccountTooManyNicks {
		nsNotice(rb, client.t("You have too many nicks reserved already (you can remove some with /NS DROP)"))
	} else if err == errNicknameReserved {
		nsNotice(rb, client.t("That nickname is already reserved by someone else"))
	} else {
		nsNotice(rb, client.t("Error reserving nickname"))
	}
}

func nsLoginThrottleCheck(client *Client, rb *ResponseBuffer) (success bool) {
	throttled, remainingTime := client.loginThrottle.Touch()
	if throttled {
		nsNotice(rb, fmt.Sprintf(client.t("Please wait at least %v and try again"), remainingTime))
		return false
	}
	return true
}

func nsIdentifyHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	if client.LoggedIntoAccount() {
		nsNotice(rb, client.t("You're already logged into an account"))
		return
	}

	loginSuccessful := false

	var username, passphrase string
	if len(params) == 1 {
		if client.certfp != "" {
			username = params[0]
		} else {
			// XXX undocumented compatibility mode with other nickservs, allowing
			// /msg NickServ identify passphrase
			username = client.NickCasefolded()
			passphrase = params[0]
		}
	} else {
		username = params[0]
		passphrase = params[1]
	}

	// try passphrase
	if passphrase != "" {
		if !nsLoginThrottleCheck(client, rb) {
			return
		}
		err := server.accounts.AuthenticateByPassphrase(client, username, passphrase)
		loginSuccessful = (err == nil)
	}

	// try certfp
	if !loginSuccessful && client.certfp != "" {
		err := server.accounts.AuthenticateByCertFP(client)
		loginSuccessful = (err == nil)
	}

	if loginSuccessful {
		sendSuccessfulSaslAuth(client, rb, true)
	} else {
		nsNotice(rb, client.t("Could not login with your TLS certificate or supplied username/password"))
	}
}

func nsInfoHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	var accountName string
	if len(params) > 0 {
		nick := params[0]
		if server.AccountConfig().NickReservation.Enabled {
			accountName = server.accounts.NickToAccount(nick)
			if accountName == "" {
				nsNotice(rb, client.t("That nickname is not registered"))
				return
			}
		} else {
			accountName = nick
		}
	} else {
		accountName = client.Account()
		if accountName == "" {
			nsNotice(rb, client.t("You're not logged into an account"))
			return
		}
	}

	account, err := server.accounts.LoadAccount(accountName)
	if err != nil || !account.Verified {
		nsNotice(rb, client.t("Account does not exist"))
		return
	}

	nsNotice(rb, fmt.Sprintf(client.t("Account: %s"), account.Name))
	registeredAt := account.RegisteredAt.Format("Jan 02, 2006 15:04:05Z")
	nsNotice(rb, fmt.Sprintf(client.t("Registered at: %s"), registeredAt))
	// TODO nicer formatting for this
	for _, nick := range account.AdditionalNicks {
		nsNotice(rb, fmt.Sprintf(client.t("Additional grouped nick: %s"), nick))
	}
	for _, channel := range server.accounts.ChannelsForAccount(accountName) {
		nsNotice(rb, fmt.Sprintf(client.t("Registered channel: %s"), channel))
	}
}

func nsRegisterHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	// get params
	account, email := params[0], params[1]
	var passphrase string
	if len(params) > 2 {
		passphrase = params[2]
	}

	certfp := client.certfp
	if passphrase == "" && certfp == "" {
		nsNotice(rb, client.t("You need to either supply a passphrase or be connected via TLS with a client cert"))
		return
	}

	if client.LoggedIntoAccount() {
		nsNotice(rb, client.t("You're already logged into an account"))
		return
	}

	if !nsLoginThrottleCheck(client, rb) {
		return
	}

	config := server.AccountConfig()
	var callbackNamespace, callbackValue string
	noneCallbackAllowed := false
	for _, callback := range config.Registration.EnabledCallbacks {
		if callback == "*" {
			noneCallbackAllowed = true
		}
	}
	// XXX if ACC REGISTER allows registration with the `none` callback, then ignore
	// any callback that was passed here (to avoid confusion in the case where the ircd
	// has no mail server configured). otherwise, register using the provided callback:
	if noneCallbackAllowed {
		callbackNamespace = "*"
	} else {
		callbackNamespace, callbackValue = parseCallback(email, config)
		if callbackNamespace == "" {
			nsNotice(rb, client.t("Registration requires a valid e-mail address"))
			return
		}
	}

	err := server.accounts.Register(client, account, callbackNamespace, callbackValue, passphrase, client.certfp)
	if err == nil {
		if callbackNamespace == "*" {
			err = server.accounts.Verify(client, account, "")
			if err == nil {
				sendSuccessfulRegResponse(client, rb, true)
			}
		} else {
			messageTemplate := client.t("Account created, pending verification; verification code has been sent to %s:%s")
			message := fmt.Sprintf(messageTemplate, callbackNamespace, callbackValue)
			nsNotice(rb, message)
		}
	}

	// details could not be stored and relevant numerics have been dispatched, abort
	if err != nil {
		errMsg, _ := registrationErrorToMessageAndCode(err)
		nsNotice(rb, errMsg)
		return
	}
}

func nsSaregisterHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	account, passphrase := params[0], params[1]
	err := server.accounts.Register(nil, account, "admin", "", passphrase, "")
	if err == nil {
		err = server.accounts.Verify(nil, account, "")
	}

	if err != nil {
		var errMsg string
		if err == errAccountAlreadyRegistered || err == errAccountAlreadyVerified {
			errMsg = client.t("Account already exists")
		} else if err == errAccountBadPassphrase {
			errMsg = client.t("Passphrase contains forbidden characters or is otherwise invalid")
		} else {
			server.logger.Error("services", "unknown error from saregister", err.Error())
			errMsg = client.t("Could not register")
		}
		nsNotice(rb, errMsg)
	} else {
		nsNotice(rb, fmt.Sprintf(client.t("Successfully registered account %s"), account))
	}
}

func nsUnregisterHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	username := params[0]
	var verificationCode string
	if len(params) > 1 {
		verificationCode = params[1]
	}

	if username == "" {
		nsNotice(rb, client.t("You must specify an account"))
		return
	}

	account, err := server.accounts.LoadAccount(username)
	if err == errAccountDoesNotExist {
		nsNotice(rb, client.t("Invalid account name"))
		return
	} else if err != nil {
		nsNotice(rb, client.t("Internal error"))
		return
	}

	cfname, _ := CasefoldName(username)
	if !(cfname == client.Account() || client.HasRoleCapabs("accreg")) {
		nsNotice(rb, client.t("Insufficient oper privs"))
		return
	}

	expectedCode := unregisterConfirmationCode(account.Name, account.RegisteredAt)
	if expectedCode != verificationCode {
		nsNotice(rb, ircfmt.Unescape(client.t("$bWarning: unregistering this account will remove its stored privileges.$b")))
		nsNotice(rb, fmt.Sprintf(client.t("To confirm account unregistration, type: /NS UNREGISTER %s %s"), cfname, expectedCode))
		return
	}

	err = server.accounts.Unregister(cfname)
	if err == errAccountDoesNotExist {
		nsNotice(rb, client.t(err.Error()))
	} else if err != nil {
		nsNotice(rb, client.t("Error while unregistering account"))
	} else {
		nsNotice(rb, fmt.Sprintf(client.t("Successfully unregistered account %s"), cfname))
		server.logger.Info("accounts", "client", client.Nick(), "unregistered account", cfname)
	}
}

func nsVerifyHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	username, code := params[0], params[1]
	err := server.accounts.Verify(client, username, code)

	var errorMessage string
	if err == errAccountVerificationInvalidCode || err == errAccountAlreadyVerified {
		errorMessage = err.Error()
	} else if err != nil {
		errorMessage = errAccountVerificationFailed.Error()
	}

	if errorMessage != "" {
		nsNotice(rb, client.t(errorMessage))
		return
	}

	sendSuccessfulRegResponse(client, rb, true)
}

func nsPasswdHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	var target string
	var newPassword string
	var errorMessage string

	hasPrivs := client.HasRoleCapabs("accreg")
	if !hasPrivs && !nsLoginThrottleCheck(client, rb) {
		return
	}

	switch len(params) {
	case 2:
		if !hasPrivs {
			errorMessage = "Insufficient privileges"
		} else {
			target, newPassword = params[0], params[1]
		}
	case 3:
		target = client.Account()
		if target == "" {
			errorMessage = "You're not logged into an account"
		} else if params[1] != params[2] {
			errorMessage = "Passwords do not match"
		} else {
			// check that they correctly supplied the preexisting password
			_, err := server.accounts.checkPassphrase(target, params[0])
			if err != nil {
				errorMessage = "Password incorrect"
			} else {
				newPassword = params[1]
			}
		}
	default:
		errorMessage = "Invalid parameters"
	}

	if errorMessage != "" {
		nsNotice(rb, client.t(errorMessage))
		return
	}

	err := server.accounts.setPassword(target, newPassword)
	if err == nil {
		nsNotice(rb, client.t("Password changed"))
	} else {
		server.logger.Error("internal", "could not upgrade user password:", err.Error())
		nsNotice(rb, client.t("Password could not be changed due to server error"))
	}
}

func nsEnforceHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	if len(params) == 0 {
		status := server.accounts.getStoredEnforcementStatus(client.Account())
		nsNotice(rb, fmt.Sprintf(client.t("Your current nickname enforcement is: %s"), status))
	} else {
		method, err := nickReservationFromString(params[0])
		if err != nil {
			nsNotice(rb, client.t("Invalid parameters"))
			return
		}
		err = server.accounts.SetEnforcementStatus(client.Account(), method)
		if err == nil {
			nsNotice(rb, client.t("Enforcement method set"))
		} else {
			server.logger.Error("internal", "couldn't store NS ENFORCE data", err.Error())
			nsNotice(rb, client.t("An error occurred"))
		}
	}
}
