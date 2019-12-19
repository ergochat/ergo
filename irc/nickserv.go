// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/goshuirc/irc-go/ircfmt"

	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/sno"
	"github.com/oragono/oragono/irc/utils"
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

func servCmdRequiresBouncerEnabled(config *Config) bool {
	return config.Accounts.Bouncer.Enabled
}

const (
	nsPrefix = "NickServ!NickServ@localhost"
	// ZNC's nickserv module will not detect this unless it is:
	// 1. sent with prefix `nickserv`
	// 2. contains the string "identify"
	// 3. contains at least one of several other magic strings ("msg" works)
	nsTimeoutNotice = `This nickname is reserved. Please login within %v (using $b/msg NickServ IDENTIFY <password>$b or SASL), or switch to a different nickname.`
)

const nickservHelp = `NickServ lets you register and log into an account.`

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
			hidden:  true,
			handler: nsEnforceHandler,
			help: `Syntax: $bENFORCE [method]$b

ENFORCE is an alias for $bGET enforce$b and $bSET enforce$b. See the help
entry for $bSET$b for more information.`,
			authRequired: true,
			enabled:      servCmdRequiresAccreg,
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

GROUP links your current nickname with your logged-in account, so other people
will not be able to use it.`,
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
			help: `Syntax: $bREGISTER <password> [email]$b

REGISTER lets you register your current nickname as a user account. If the
server allows anonymous registration, you can omit the e-mail address.

If you are currently logged in with a TLS client certificate and wish to use
it instead of a password to log in, send * as the password.`,
			helpShort: `$bREGISTER$b lets you register a user account.`,
			enabled:   servCmdRequiresAccreg,
			minParams: 1,
			maxParams: 2,
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
		"sessions": {
			handler: nsSessionsHandler,
			help: `Syntax: $bSESSIONS [nickname]$b

SESSIONS lists information about the sessions currently attached, via
the server's bouncer functionality, to your nickname. An administrator
can use this command to list another user's sessions.`,
			helpShort: `$bSESSIONS$b lists the sessions attached to a nickname.`,
			enabled:   servCmdRequiresBouncerEnabled,
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
		"get": {
			handler: nsGetHandler,
			help: `Syntax: $bGET <setting>$b

GET queries the current values of your account settings. For more information
on the settings and their possible values, see HELP SET.`,
			helpShort:    `$bGET$b queries the current values of your account settings`,
			authRequired: true,
			enabled:      servCmdRequiresAccreg,
			minParams:    1,
		},
		"saget": {
			handler: nsGetHandler,
			help: `Syntax: $bSAGET <account> <setting>$b

SAGET queries the values of someone else's account settings. For more
information on the settings and their possible values, see HELP SET.`,
			helpShort: `$bSAGET$b queries the current values of another user's account settings`,
			enabled:   servCmdRequiresAccreg,
			minParams: 2,
			capabs:    []string{"accreg"},
		},
		"set": {
			handler:   nsSetHandler,
			helpShort: `$bSET$b modifies your account settings`,
			// these are broken out as separate strings so they can be translated separately
			helpStrings: []string{
				`Syntax $bSET <setting> <value>$b

Set modifies your account settings. The following settings are available:`,

				`$bENFORCE$b
'enforce' lets you specify a custom enforcement mechanism for your registered
nicknames. Your options are:
1. 'none'    [no enforcement, overriding the server default]
2. 'timeout' [anyone using the nick must authenticate before a deadline,
              or else they will be renamed]
3. 'strict'  [you must already be authenticated to use the nick]
4. 'default' [use the server default]`,

				`$bBOUNCER$b
If 'bouncer' is enabled and you are already logged in and using a nick, a
second client of yours that authenticates with SASL and requests the same nick
is allowed to attach to the nick as well (this is comparable to the behavior
of IRC "bouncers" like ZNC). Your options are 'on' (allow this behavior),
'off' (disallow it), and 'default' (use the server default value).`,

				`$bAUTOREPLAY-LINES$b
'autoreplay-lines' controls the number of lines of channel history that will
be replayed to you automatically when joining a channel. Your options are any
positive number, 0 to disable the feature, and 'default' to use the server
default.`,

				`$bREPLAY-JOINS$b
'replay-joins' controls whether replayed channel history will include
lines for join and part. This provides more information about the context of
messages, but may be spammy. Your options are 'always', 'never', and the default
of 'commands-only' (the messages will be replayed in /HISTORY output, but not
during autoreplay).`,
			},
			authRequired: true,
			enabled:      servCmdRequiresAccreg,
			minParams:    2,
		},
		"saset": {
			handler: nsSetHandler,
			help: `Syntax: $bSASET <account> <setting> <value>$b

SASET modifies the values of someone else's account settings. For more
information on the settings and their possible values, see HELP SET.`,
			helpShort: `$bSASET$b modifies another user's account settings`,
			enabled:   servCmdRequiresAccreg,
			minParams: 3,
			capabs:    []string{"accreg"},
		},
	}
)

// nsNotice sends the client a notice from NickServ
func nsNotice(rb *ResponseBuffer, text string) {
	// XXX i can't figure out how to use OragonoServices[servicename].prefix here
	// without creating a compile-time initialization loop
	rb.Add(nil, nsPrefix, "NOTICE", rb.target.Nick(), text)
}

func nsGetHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	var account string
	if command == "saget" {
		account = params[0]
		params = params[1:]
	} else {
		account = client.Account()
	}

	accountData, err := server.accounts.LoadAccount(account)
	if err == errAccountDoesNotExist {
		nsNotice(rb, client.t("No such account"))
		return
	} else if err != nil {
		nsNotice(rb, client.t("Error loading account data"))
		return
	}

	displaySetting(params[0], accountData.Settings, client, rb)
}

func displaySetting(settingName string, settings AccountSettings, client *Client, rb *ResponseBuffer) {
	config := client.server.Config()
	switch strings.ToLower(settingName) {
	case "enforce":
		storedValue := settings.NickEnforcement
		serializedStoredValue := nickReservationToString(storedValue)
		nsNotice(rb, fmt.Sprintf(client.t("Your stored nickname enforcement setting is: %s"), serializedStoredValue))
		serializedActualValue := nickReservationToString(configuredEnforcementMethod(config, storedValue))
		nsNotice(rb, fmt.Sprintf(client.t("Given current server settings, your nickname is enforced with: %s"), serializedActualValue))
	case "autoreplay-lines":
		if settings.AutoreplayLines == nil {
			nsNotice(rb, fmt.Sprintf(client.t("You will receive the server default of %d lines of autoreplayed history"), config.History.AutoreplayOnJoin))
		} else {
			nsNotice(rb, fmt.Sprintf(client.t("You will receive %d lines of autoreplayed history"), *settings.AutoreplayLines))
		}
	case "replay-joins":
		switch settings.ReplayJoins {
		case ReplayJoinsCommandsOnly:
			nsNotice(rb, client.t("You will see JOINs and PARTs in /HISTORY output, but not in autoreplay"))
		case ReplayJoinsAlways:
			nsNotice(rb, client.t("You will see JOINs and PARTs in /HISTORY output and in autoreplay"))
		case ReplayJoinsNever:
			nsNotice(rb, client.t("You will not see JOINs and PARTs in /HISTORY output or in autoreplay"))
		}
	case "bouncer":
		if !config.Accounts.Bouncer.Enabled {
			nsNotice(rb, fmt.Sprintf(client.t("This feature has been disabled by the server administrators")))
		} else {
			switch settings.AllowBouncer {
			case BouncerAllowedServerDefault:
				if config.Accounts.Bouncer.AllowedByDefault {
					nsNotice(rb, fmt.Sprintf(client.t("Bouncer functionality is currently enabled for your account, but you can opt out")))
				} else {
					nsNotice(rb, fmt.Sprintf(client.t("Bouncer functionality is currently disabled for your account, but you can opt in")))
				}
			case BouncerDisallowedByUser:
				nsNotice(rb, fmt.Sprintf(client.t("Bouncer functionality is currently disabled for your account")))
			case BouncerAllowedByUser:
				nsNotice(rb, fmt.Sprintf(client.t("Bouncer functionality is currently enabled for your account")))
			}
		}
	default:
		nsNotice(rb, client.t("No such setting"))
	}
}

func nsSetHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	var account string
	if command == "saset" {
		account = params[0]
		params = params[1:]
	} else {
		account = client.Account()
	}

	var munger settingsMunger
	var finalSettings AccountSettings
	var err error
	switch strings.ToLower(params[0]) {
	case "pass":
		nsNotice(rb, client.t("To change a password, use the PASSWD command. For details, /msg NickServ HELP PASSWD"))
		return
	case "enforce":
		var method NickEnforcementMethod
		method, err = nickReservationFromString(params[1])
		if err != nil {
			err = errInvalidParams
			break
		}
		// updating enforcement settings is special-cased, because it requires
		// an update to server.accounts.accountToMethod
		finalSettings, err = server.accounts.SetEnforcementStatus(account, method)
		if err == nil {
			finalSettings.NickEnforcement = method // success
		}
	case "autoreplay-lines":
		var newValue *int
		if strings.ToLower(params[1]) != "default" {
			val, err_ := strconv.Atoi(params[1])
			if err_ != nil || val < 0 {
				err = errInvalidParams
				break
			}
			newValue = new(int)
			*newValue = val
		}
		munger = func(in AccountSettings) (out AccountSettings, err error) {
			out = in
			out.AutoreplayLines = newValue
			return
		}
	case "bouncer":
		var newValue BouncerAllowedSetting
		if strings.ToLower(params[1]) == "default" {
			newValue = BouncerAllowedServerDefault
		} else {
			var enabled bool
			enabled, err = utils.StringToBool(params[1])
			if enabled {
				newValue = BouncerAllowedByUser
			} else {
				newValue = BouncerDisallowedByUser
			}
		}
		if err == nil {
			munger = func(in AccountSettings) (out AccountSettings, err error) {
				out = in
				out.AllowBouncer = newValue
				return
			}
		}
	case "replay-joins":
		var newValue ReplayJoinsSetting
		newValue, err = replayJoinsSettingFromString(params[1])
		if err == nil {
			munger = func(in AccountSettings) (out AccountSettings, err error) {
				out = in
				out.ReplayJoins = newValue
				return
			}
		}
	default:
		err = errInvalidParams
	}

	if munger != nil {
		finalSettings, err = server.accounts.ModifyAccountSettings(account, munger)
	}

	switch err {
	case nil:
		nsNotice(rb, client.t("Successfully changed your account settings"))
		displaySetting(params[0], finalSettings, client, rb)
	case errInvalidParams, errAccountDoesNotExist, errFeatureDisabled, errAccountUnverified, errAccountUpdateFailed:
		nsNotice(rb, client.t(err.Error()))
	default:
		// unknown error
		nsNotice(rb, client.t("An error occurred"))
	}
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

	ghost.Quit(fmt.Sprintf(ghost.t("GHOSTed by %s"), client.Nick()), nil)
	ghost.destroy(nil)
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
		sendSuccessfulAccountAuth(client, rb, true, true)
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
	details := client.Details()
	account := details.nick
	passphrase := params[0]
	var email string
	if 1 < len(params) {
		email = params[1]
	}

	certfp := client.certfp
	if passphrase == "*" {
		if certfp == "" {
			nsNotice(rb, client.t("You must be connected with TLS and a client certificate to do this"))
			return
		} else {
			passphrase = ""
		}
	}

	if details.account != "" {
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
		if callbackNamespace == "" || callbackValue == "" {
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
			messageTemplate := client.t("Account created, pending verification; verification code has been sent to %s")
			message := fmt.Sprintf(messageTemplate, fmt.Sprintf("%s:%s", callbackNamespace, callbackValue))
			nsNotice(rb, message)
		}
	}

	// details could not be stored and relevant numerics have been dispatched, abort
	message, _ := registrationErrorToMessageAndCode(err)
	if err != nil {
		nsNotice(rb, client.t(message))
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
		server.snomasks.Send(sno.LocalAccounts, fmt.Sprintf(ircfmt.Unescape("Operator $c[grey][$r%s$c[grey]] registered account $c[grey][$r%s$c[grey]] with SAREGISTER"), client.Oper().Name, account))
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
		nsNotice(rb, fmt.Sprintf(client.t("To confirm account unregistration, type: /NS UNREGISTER %[1]s %[2]s"), cfname, expectedCode))
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

	client.server.snomasks.Send(sno.LocalAccounts, fmt.Sprintf(ircfmt.Unescape("Client $c[grey][$r%s$c[grey]] unregistered account $c[grey][$r%s$c[grey]]"), client.NickMaskString(), account.Name))
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
		errorMessage = `Invalid parameters`
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
	newParams := []string{"enforce"}
	if len(params) == 0 {
		nsGetHandler(server, client, "get", newParams, rb)
	} else {
		newParams = append(newParams, params[0])
		nsSetHandler(server, client, "set", newParams, rb)
	}
}

func nsSessionsHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	target := client

	if 0 < len(params) {
		target = server.clients.Get(params[0])
		if target == nil {
			nsNotice(rb, client.t("No such nick"))
			return
		}
		// same permissions check as RPL_WHOISACTUALLY for now:
		if target != client && !client.HasMode(modes.Operator) {
			nsNotice(rb, client.t("Command restricted"))
			return
		}
	}

	sessionData, currentIndex := target.AllSessionData(rb.session)
	nsNotice(rb, fmt.Sprintf(client.t("Nickname %[1]s has %[2]d attached session(s)"), target.Nick(), len(sessionData)))
	for i, session := range sessionData {
		if currentIndex == i {
			nsNotice(rb, fmt.Sprintf(client.t("Session %d (currently attached session):"), i+1))
		} else {
			nsNotice(rb, fmt.Sprintf(client.t("Session %d:"), i+1))
		}
		nsNotice(rb, fmt.Sprintf(client.t("IP address:  %s"), session.ip.String()))
		nsNotice(rb, fmt.Sprintf(client.t("Hostname:    %s"), session.hostname))
		nsNotice(rb, fmt.Sprintf(client.t("Created at:  %s"), session.ctime.Format(time.RFC1123)))
		nsNotice(rb, fmt.Sprintf(client.t("Last active: %s"), session.atime.Format(time.RFC1123)))
	}
}
