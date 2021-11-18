// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ergochat/irc-go/ircfmt"

	"github.com/ergochat/ergo/irc/custime"
	"github.com/ergochat/ergo/irc/passwd"
	"github.com/ergochat/ergo/irc/sno"
	"github.com/ergochat/ergo/irc/utils"
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
	return config.Accounts.Multiclient.Enabled
}

func servCmdRequiresEmailReset(config *Config) bool {
	return config.Accounts.Registration.EmailVerification.Enabled &&
		config.Accounts.Registration.EmailVerification.PasswordReset.Enabled
}

const nickservHelp = `NickServ lets you register, log in to, and manage an account.`

var (
	nickservCommands = map[string]*serviceCommand{
		"clients": {
			handler: nsClientsHandler,
			help: `Syntax: $bCLIENTS LIST [nickname]$b

CLIENTS LIST shows information about the clients currently attached, via
the server's multiclient functionality, to your nickname. An administrator
can use this command to list another user's clients.

Syntax: $bCLIENTS LOGOUT [nickname] [client_id/all]$b

CLIENTS LOGOUT detaches a single client, or all clients currently attached
to your nickname. An administrator can use this command to logout another
user's clients.`,
			helpShort: `$bCLIENTS$b can list and logout the sessions attached to a nickname.`,
			enabled:   servCmdRequiresBouncerEnabled,
			minParams: 1,
		},
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
			enabled:      servCmdRequiresNickRes,
		},
		"ghost": {
			handler: nsGhostHandler,
			help: `Syntax: $bGHOST <nickname>$b

GHOST disconnects the given user from the network if they're logged in with the
same user account, letting you reclaim your nickname.`,
			helpShort:    `$bGHOST$b reclaims your nickname.`,
			enabled:      servCmdRequiresNickRes,
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
			enabled:   servCmdRequiresAuthEnabled,
			minParams: 1,
		},
		"list": {
			handler: nsListHandler,
			help: `Syntax: $bLIST [regex]$b

LIST returns the list of registered nicknames, which match the given regex.
If no regex is provided, all registered nicknames are returned.`,
			helpShort: `$bLIST$b searches the list of registered nicknames.`,
			enabled:   servCmdRequiresAuthEnabled,
			capabs:    []string{"accreg"},
			minParams: 0,
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
			help: `Syntax: $bSAREGISTER <username> [password]$b

SAREGISTER registers an account on someone else's behalf.
This is for use in configurations that require SASL for all connections;
an administrator can set use this command to set up user accounts.`,
			helpShort: `$bSAREGISTER$b registers an account on someone else's behalf.`,
			enabled:   servCmdRequiresAuthEnabled,
			capabs:    []string{"accreg"},
			minParams: 1,
		},
		"sessions": {
			hidden:  true,
			handler: nsClientsHandler,
			help: `Syntax: $bSESSIONS [nickname]$b

SESSIONS is an alias for $bCLIENTS LIST$b. See the help entry for $bCLIENTS$b
for more information.`,
			enabled: servCmdRequiresBouncerEnabled,
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
		"erase": {
			handler: nsUnregisterHandler,
			help: `Syntax: $bERASE <username> [code]$b

ERASE deletes all records of an account, allowing it to be re-registered.
This should be used with caution, because it violates an expectation that
account names are permanent identifiers. Typically, UNREGISTER should be
used instead. A confirmation code is required; invoking the command
without a code will display the necessary code.`,
			helpShort: `$bERASE$b erases all records of an account, allowing reuse.`,
			enabled:   servCmdRequiresAuthEnabled,
			capabs:    []string{"accreg"},
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
password by supplying their username and then the desired password. To
indicate an empty password, use * instead.`,
			helpShort: `$bPASSWD$b lets you change your password.`,
			enabled:   servCmdRequiresAuthEnabled,
			minParams: 2,
		},
		"password": {
			aliasOf: "passwd",
		},
		"get": {
			handler: nsGetHandler,
			help: `Syntax: $bGET <setting>$b

GET queries the current values of your account settings. For more information
on the settings and their possible values, see HELP SET.`,
			helpShort:    `$bGET$b queries the current values of your account settings`,
			authRequired: true,
			enabled:      servCmdRequiresAuthEnabled,
			minParams:    1,
		},
		"saget": {
			handler: nsGetHandler,
			help: `Syntax: $bSAGET <account> <setting>$b

SAGET queries the values of someone else's account settings. For more
information on the settings and their possible values, see HELP SET.`,
			helpShort: `$bSAGET$b queries the current values of another user's account settings`,
			enabled:   servCmdRequiresAuthEnabled,
			minParams: 2,
			capabs:    []string{"accreg"},
		},
		"set": {
			handler:   nsSetHandler,
			helpShort: `$bSET$b modifies your account settings`,
			// these are broken out as separate strings so they can be translated separately
			helpStrings: []string{
				`Syntax $bSET <setting> <value>$b

SET modifies your account settings. The following settings are available:`,

				`$bENFORCE$b
'enforce' lets you specify a custom enforcement mechanism for your registered
nicknames. Your options are:
1. 'none'    [no enforcement, overriding the server default]
2. 'strict'  [you must already be authenticated to use the nick]
3. 'default' [use the server default]`,

				`$bMULTICLIENT$b
If 'multiclient' is enabled and you are already logged in and using a nick, a
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
messages, but may be spammy. Your options are 'always' and the default of
'commands-only' (the messages will be replayed in CHATHISTORY output, but not
during autoreplay).`,
				`$bALWAYS-ON$b
'always-on' controls whether your nickname/identity will remain active
even while you are disconnected from the server. Your options are 'true',
'false', and 'default' (use the server default value).`,
				`$bAUTOREPLAY-MISSED$b
'autoreplay-missed' is only effective for always-on clients. If enabled,
if you have at most one active session, the server will remember the time
you disconnect and then replay missed messages to you when you reconnect.
Your options are 'on' and 'off'.`,
				`$bDM-HISTORY$b
'dm-history' is only effective for always-on clients. It lets you control
how the history of your direct messages is stored. Your options are:
1. 'off'        [no history]
2. 'ephemeral'  [a limited amount of temporary history, not stored on disk]
3. 'on'         [history stored in a permanent database, if available]
4. 'default'    [use the server default]`,
				`$bAUTO-AWAY$b
'auto-away' is only effective for always-on clients. If enabled, you will
automatically be marked away when all your sessions are disconnected, and
automatically return from away when you connect again.`,
				`$bEMAIL$b
'email' controls the e-mail address associated with your account (if the
server operator allows it, this address can be used for password resets).
As an additional security measure, if you have a password set, you must
provide it as an additional argument to $bSET$b, for example,
SET EMAIL test@example.com hunter2`,
			},
			authRequired: true,
			enabled:      servCmdRequiresAuthEnabled,
			minParams:    2,
		},
		"saset": {
			handler: nsSetHandler,
			help: `Syntax: $bSASET <account> <setting> <value>$b

SASET modifies the values of someone else's account settings. For more
information on the settings and their possible values, see HELP SET.`,
			helpShort: `$bSASET$b modifies another user's account settings`,
			enabled:   servCmdRequiresAuthEnabled,
			minParams: 3,
			capabs:    []string{"accreg"},
		},
		"sendpass": {
			handler: nsSendpassHandler,
			help: `Syntax: $bSENDPASS <account>$b

SENDPASS sends a password reset email to the email address associated with
the target account. The reset code in the email can then be used with the
$bRESETPASS$b command.`,
			helpShort: `$bSENDPASS$b initiates an email-based password reset`,
			enabled:   servCmdRequiresEmailReset,
			minParams: 1,
		},
		"resetpass": {
			handler: nsResetpassHandler,
			help: `Syntax: $bRESETPASS <account> <code> <password>$b

RESETPASS resets an account password, using a reset code that was emailed as
the result of a previous $bSENDPASS$b command.`,
			helpShort: `$bRESETPASS$b completes an email-based password reset`,
			enabled:   servCmdRequiresEmailReset,
			minParams: 3,
		},
		"cert": {
			handler: nsCertHandler,
			help: `Syntax: $bCERT <LIST | ADD | DEL> [account] [certfp]$b

CERT examines or modifies the SHA-256 TLS certificate fingerprints that can
be used to log into an account. Specifically, $bCERT LIST$b lists the
authorized fingerprints, $bCERT ADD <fingerprint>$b adds a new fingerprint, and
$bCERT DEL <fingerprint>$b removes a fingerprint. If you're an IRC operator
with the correct permissions, you can act on another user's account, for
example with $bCERT ADD <account> <fingerprint>$b. See the operator manual
for instructions on how to compute the fingerprint.`,
			helpShort: `$bCERT$b controls a user account's certificate fingerprints`,
			enabled:   servCmdRequiresAuthEnabled,
			minParams: 1,
		},
		"suspend": {
			handler: nsSuspendHandler,
			help: `Syntax: $bSUSPEND ADD <nickname> [DURATION duration] [reason]$b
        $bSUSPEND DEL <nickname>$b
        $bSUSPEND LIST$b

Suspending an account disables it (preventing new logins) and disconnects
all associated clients. You can specify a time limit or a reason for
the suspension. The $bDEL$b subcommand reverses a suspension, and the $bLIST$b
command lists all current suspensions.`,
			helpShort: `$bSUSPEND$b manages account suspensions`,
			minParams: 1,
			capabs:    []string{"ban"},
		},
		"rename": {
			handler: nsRenameHandler,
			help: `Syntax: $bRENAME <account> <newname>$b

RENAME allows a server administrator to change the name of an account.
Currently, you can only change the canonical casefolding of an account
(e.g., you can change "Alice" to "alice", but not "Alice" to "Amanda").`,
			helpShort: `$bRENAME$b renames an account`,
			minParams: 2,
			capabs:    []string{"accreg"},
		},
		"verifyemail": {
			handler:      nsVerifyEmailHandler,
			authRequired: true,
			minParams:    1,
			hidden:       true,
		},
	}
)

func nsGetHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	var account string
	if command == "saget" {
		account = params[0]
		params = params[1:]
	} else {
		account = client.Account()
	}

	accountData, err := server.accounts.LoadAccount(account)
	if err == errAccountDoesNotExist {
		service.Notice(rb, client.t("No such account"))
		return
	} else if err != nil {
		service.Notice(rb, client.t("Error loading account data"))
		return
	}

	displaySetting(service, params[0], accountData.Settings, client, rb)
}

func displaySetting(service *ircService, settingName string, settings AccountSettings, client *Client, rb *ResponseBuffer) {
	config := client.server.Config()
	switch strings.ToLower(settingName) {
	case "enforce":
		storedValue := settings.NickEnforcement
		serializedStoredValue := nickReservationToString(storedValue)
		service.Notice(rb, fmt.Sprintf(client.t("Your stored nickname enforcement setting is: %s"), serializedStoredValue))
		serializedActualValue := nickReservationToString(configuredEnforcementMethod(config, storedValue))
		service.Notice(rb, fmt.Sprintf(client.t("Given current server settings, your nickname is enforced with: %s"), serializedActualValue))
	case "autoreplay-lines":
		if settings.AutoreplayLines == nil {
			service.Notice(rb, fmt.Sprintf(client.t("You will receive the server default of %d lines of autoreplayed history"), config.History.AutoreplayOnJoin))
		} else {
			service.Notice(rb, fmt.Sprintf(client.t("You will receive %d lines of autoreplayed history"), *settings.AutoreplayLines))
		}
	case "replay-joins":
		switch settings.ReplayJoins {
		case ReplayJoinsCommandsOnly:
			service.Notice(rb, client.t("You will see JOINs and PARTs in /HISTORY output, but not in autoreplay"))
		case ReplayJoinsAlways:
			service.Notice(rb, client.t("You will see JOINs and PARTs in /HISTORY output and in autoreplay"))
		}
	case "multiclient":
		if !config.Accounts.Multiclient.Enabled {
			service.Notice(rb, client.t("This feature has been disabled by the server administrators"))
		} else {
			switch settings.AllowBouncer {
			case MulticlientAllowedServerDefault:
				if config.Accounts.Multiclient.AllowedByDefault {
					service.Notice(rb, client.t("Multiclient functionality is currently enabled for your account, but you can opt out"))
				} else {
					service.Notice(rb, client.t("Multiclient functionality is currently disabled for your account, but you can opt in"))
				}
			case MulticlientDisallowedByUser:
				service.Notice(rb, client.t("Multiclient functionality is currently disabled for your account"))
			case MulticlientAllowedByUser:
				service.Notice(rb, client.t("Multiclient functionality is currently enabled for your account"))
			}
		}
	case "always-on":
		stored := settings.AlwaysOn
		actual := persistenceEnabled(config.Accounts.Multiclient.AlwaysOn, stored)
		service.Notice(rb, fmt.Sprintf(client.t("Your stored always-on setting is: %s"), userPersistentStatusToString(stored)))
		if actual {
			service.Notice(rb, client.t("Given current server settings, your client is always-on"))
		} else {
			service.Notice(rb, client.t("Given current server settings, your client is not always-on"))
		}
	case "autoreplay-missed":
		stored := settings.AutoreplayMissed
		if stored {
			alwaysOn := persistenceEnabled(config.Accounts.Multiclient.AlwaysOn, settings.AlwaysOn)
			if alwaysOn {
				service.Notice(rb, client.t("Autoreplay of missed messages is enabled"))
			} else {
				service.Notice(rb, client.t("You have enabled autoreplay of missed messages, but you can't receive them because your client isn't set to always-on"))
			}
		} else {
			service.Notice(rb, client.t("Your account is not configured to receive autoreplayed missed messages"))
		}
	case "auto-away":
		stored := settings.AutoAway
		alwaysOn := persistenceEnabled(config.Accounts.Multiclient.AlwaysOn, settings.AlwaysOn)
		actual := persistenceEnabled(config.Accounts.Multiclient.AutoAway, settings.AutoAway)
		service.Notice(rb, fmt.Sprintf(client.t("Your stored auto-away setting is: %s"), userPersistentStatusToString(stored)))
		if actual && alwaysOn {
			service.Notice(rb, client.t("Given current server settings, auto-away is enabled for your client"))
		} else if actual && !alwaysOn {
			service.Notice(rb, client.t("Because your client is not always-on, auto-away is disabled"))
		} else if !actual {
			service.Notice(rb, client.t("Given current server settings, auto-away is disabled for your client"))
		}
	case "dm-history":
		effectiveValue := historyEnabled(config.History.Persistent.DirectMessages, settings.DMHistory)
		service.Notice(rb, fmt.Sprintf(client.t("Your stored direct message history setting is: %s"), historyStatusToString(settings.DMHistory)))
		service.Notice(rb, fmt.Sprintf(client.t("Given current server settings, your direct message history setting is: %s"), historyStatusToString(effectiveValue)))
	case "email":
		if settings.Email != "" {
			service.Notice(rb, fmt.Sprintf(client.t("Your stored e-mail address is: %s"), settings.Email))
		} else {
			service.Notice(rb, client.t("You have no stored e-mail address"))
		}
	default:
		service.Notice(rb, client.t("No such setting"))
	}
}

func userPersistentStatusToString(status PersistentStatus) string {
	// #1544: "mandatory" as a user setting should display as "enabled"
	result := persistentStatusToString(status)
	if result == "mandatory" {
		result = "enabled"
	}
	return result
}

func nsSetHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	var privileged bool
	var account string
	if command == "saset" {
		privileged = true
		account = params[0]
		params = params[1:]
	} else {
		account = client.Account()
	}

	key := strings.ToLower(params[0])
	// unprivileged NS SET EMAIL is different because it requires a confirmation
	if !privileged && key == "email" {
		nsSetEmailHandler(service, client, params, rb)
		return
	}

	var munger settingsMunger
	var finalSettings AccountSettings
	var err error
	switch key {
	case "pass", "password":
		service.Notice(rb, client.t("To change a password, use the PASSWD command. For details, /msg NickServ HELP PASSWD"))
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
	case "multiclient":
		var newValue MulticlientAllowedSetting
		if strings.ToLower(params[1]) == "default" {
			newValue = MulticlientAllowedServerDefault
		} else {
			var enabled bool
			enabled, err = utils.StringToBool(params[1])
			if enabled {
				newValue = MulticlientAllowedByUser
			} else {
				newValue = MulticlientDisallowedByUser
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
	case "always-on":
		// #821: it's problematic to alter the value of always-on if you're not
		// the (actual or potential) always-on client yourself. make an exception
		// for `saset` to give operators an escape hatch (any consistency problems
		// can probably be fixed by restarting the server):
		if command != "saset" {
			details := client.Details()
			if details.nick != details.accountName {
				err = errNickAccountMismatch
			}
		}
		if err == nil {
			var newValue PersistentStatus
			newValue, err = persistentStatusFromString(params[1])
			// "opt-in" and "opt-out" don't make sense as user preferences
			if err == nil && newValue != PersistentOptIn && newValue != PersistentOptOut {
				munger = func(in AccountSettings) (out AccountSettings, err error) {
					out = in
					out.AlwaysOn = newValue
					return
				}
			}
		}
	case "autoreplay-missed":
		var newValue bool
		newValue, err = utils.StringToBool(params[1])
		if err == nil {
			munger = func(in AccountSettings) (out AccountSettings, err error) {
				out = in
				out.AutoreplayMissed = newValue
				return
			}
		}
	case "auto-away":
		var newValue PersistentStatus
		newValue, err = persistentStatusFromString(params[1])
		// "opt-in" and "opt-out" don't make sense as user preferences
		if err == nil && newValue != PersistentOptIn && newValue != PersistentOptOut {
			munger = func(in AccountSettings) (out AccountSettings, err error) {
				out = in
				out.AutoAway = newValue
				return
			}
		}
	case "dm-history":
		var newValue HistoryStatus
		newValue, err = historyStatusFromString(params[1])
		if err == nil {
			munger = func(in AccountSettings) (out AccountSettings, err error) {
				out = in
				out.DMHistory = newValue
				return
			}
		}
	case "email":
		newValue := params[1]
		munger = func(in AccountSettings) (out AccountSettings, err error) {
			out = in
			out.Email = newValue
			return
		}
	default:
		err = errInvalidParams
	}

	if munger != nil {
		finalSettings, err = server.accounts.ModifyAccountSettings(account, munger)
	}

	switch err {
	case nil:
		service.Notice(rb, client.t("Successfully changed your account settings"))
		displaySetting(service, key, finalSettings, client, rb)
	case errInvalidParams, errAccountDoesNotExist, errFeatureDisabled, errAccountUnverified, errAccountUpdateFailed:
		service.Notice(rb, client.t(err.Error()))
	case errNickAccountMismatch:
		service.Notice(rb, fmt.Sprintf(client.t("Your nickname must match your account name %s exactly to modify this setting. Try changing it with /NICK, or logging out and back in with the correct nickname."), client.AccountName()))
	default:
		// unknown error
		service.Notice(rb, client.t("An error occurred"))
	}
}

// handle unprivileged NS SET EMAIL, which sends a confirmation code
func nsSetEmailHandler(service *ircService, client *Client, params []string, rb *ResponseBuffer) {
	config := client.server.Config()
	if !config.Accounts.Registration.EmailVerification.Enabled {
		rb.Notice(client.t("E-mail verification is disabled"))
		return
	}
	if !nsLoginThrottleCheck(service, client, rb) {
		return
	}
	var password string
	if len(params) > 2 {
		password = params[2]
	}
	account := client.Account()
	errorMessage := nsConfirmPassword(client.server, account, password)
	if errorMessage != "" {
		service.Notice(rb, client.t(errorMessage))
		return
	}
	err := client.server.accounts.NsSetEmail(client, params[1])
	switch err {
	case nil:
		service.Notice(rb, client.t("Check your e-mail for instructions on how to confirm your change of address"))
	case errLimitExceeded:
		service.Notice(rb, client.t("Try again later"))
	default:
		// if appropriate, show the client the error from the attempted email sending
		if rErr := registrationCallbackErrorText(config, client, err); rErr != "" {
			service.Notice(rb, rErr)
		} else {
			service.Notice(rb, client.t("An error occurred"))
		}
	}
}

func nsVerifyEmailHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	err := server.accounts.NsVerifyEmail(client, params[0])
	switch err {
	case nil:
		service.Notice(rb, client.t("Successfully changed your account settings"))
		displaySetting(service, "email", client.AccountSettings(), client, rb)
	case errAccountVerificationInvalidCode:
		service.Notice(rb, client.t(err.Error()))
	default:
		service.Notice(rb, client.t("An error occurred"))
	}
}

func nsDropHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	sadrop := command == "sadrop"
	var nick string
	if len(params) > 0 {
		nick = params[0]
	} else {
		nick = client.NickCasefolded()
	}

	err := server.accounts.SetNickReserved(client, nick, sadrop, false)
	if err == nil {
		service.Notice(rb, fmt.Sprintf(client.t("Successfully ungrouped nick %s with your account"), nick))
	} else if err == errAccountNotLoggedIn {
		service.Notice(rb, client.t("You're not logged into an account"))
	} else if err == errAccountCantDropPrimaryNick {
		service.Notice(rb, client.t("You can't ungroup your primary nickname (try unregistering your account instead)"))
	} else {
		service.Notice(rb, client.t("Could not ungroup nick"))
	}
}

func nsGhostHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	nick := params[0]

	ghost := server.clients.Get(nick)
	if ghost == nil {
		service.Notice(rb, client.t("No such nick"))
		return
	} else if ghost == client {
		service.Notice(rb, client.t("You can't GHOST yourself (try /QUIT instead)"))
		return
	} else if ghost.AlwaysOn() {
		service.Notice(rb, client.t("You can't GHOST an always-on client"))
		return
	}

	authorized := false
	account := client.Account()
	if account != "" {
		// the user must either own the nick, or the target client
		authorized = (server.accounts.NickToAccount(nick) == account) || (ghost.Account() == account)
	}
	if !authorized {
		service.Notice(rb, client.t("You don't own that nick"))
		return
	}

	ghost.Quit(fmt.Sprintf(ghost.t("GHOSTed by %s"), client.Nick()), nil)
	ghost.destroy(nil)
}

func nsGroupHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	nick := client.Nick()
	err := server.accounts.SetNickReserved(client, nick, false, true)
	if err == nil {
		service.Notice(rb, fmt.Sprintf(client.t("Successfully grouped nick %s with your account"), nick))
	} else if err == errAccountTooManyNicks {
		service.Notice(rb, client.t("You have too many nicks reserved already (you can remove some with /NS DROP)"))
	} else if err == errNicknameReserved {
		service.Notice(rb, client.t("That nickname is already reserved by someone else"))
	} else {
		service.Notice(rb, client.t("Error reserving nickname"))
	}
}

func nsLoginThrottleCheck(service *ircService, client *Client, rb *ResponseBuffer) (success bool) {
	throttled, remainingTime := client.checkLoginThrottle()
	if throttled {
		service.Notice(rb, fmt.Sprintf(client.t("Please wait at least %v and try again"), remainingTime))
	}
	return !throttled
}

func nsIdentifyHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	if client.LoggedIntoAccount() {
		service.Notice(rb, client.t("You're already logged into an account"))
		return
	}

	var err error
	loginSuccessful := false

	var username, passphrase string
	if len(params) == 1 {
		if rb.session.certfp != "" {
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
		err = server.accounts.AuthenticateByPassphrase(client, username, passphrase)
		loginSuccessful = (err == nil)
	}

	// try certfp
	if !loginSuccessful && rb.session.certfp != "" {
		err = server.accounts.AuthenticateByCertificate(client, rb.session.certfp, rb.session.peerCerts, "")
		loginSuccessful = (err == nil)
	}

	nickFixupFailed := false
	if loginSuccessful {
		if !fixupNickEqualsAccount(client, rb, server.Config(), service.prefix) {
			loginSuccessful = false
			// fixupNickEqualsAccount sends its own error message, don't send another
			nickFixupFailed = true
		}
	}

	if loginSuccessful {
		sendSuccessfulAccountAuth(service, client, rb, true)
	} else if !nickFixupFailed {
		service.Notice(rb, fmt.Sprintf(client.t("Authentication failed: %s"), authErrorToMessage(server, err)))
	}
}

func nsListHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	if !client.HasRoleCapabs("accreg") {
		service.Notice(rb, client.t("Insufficient privileges"))
		return
	}

	var searchRegex *regexp.Regexp
	if len(params) > 0 {
		var err error
		searchRegex, err = regexp.Compile(params[0])
		if err != nil {
			service.Notice(rb, client.t("Invalid regex"))
			return
		}
	}

	service.Notice(rb, ircfmt.Unescape(client.t("*** $bNickServ LIST$b ***")))

	nicks := server.accounts.AllNicks()
	for _, nick := range nicks {
		if searchRegex == nil || searchRegex.MatchString(nick) {
			service.Notice(rb, fmt.Sprintf("    %s", nick))
		}
	}

	service.Notice(rb, ircfmt.Unescape(client.t("*** $bEnd of NickServ LIST$b ***")))
}

func nsInfoHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	if !server.Config().Accounts.AuthenticationEnabled && !client.HasRoleCapabs("accreg") {
		service.Notice(rb, client.t("This command has been disabled by the server administrators"))
		return
	}

	var accountName string
	if len(params) > 0 {
		nick := params[0]
		if server.Config().Accounts.NickReservation.Enabled {
			accountName = server.accounts.NickToAccount(nick)
			if accountName == "" {
				service.Notice(rb, client.t("That nickname is not registered"))
				return
			}
		} else {
			accountName = nick
		}
	} else {
		accountName = client.Account()
		if accountName == "" {
			service.Notice(rb, client.t("You're not logged into an account"))
			return
		}
	}

	account, err := server.accounts.LoadAccount(accountName)
	if err != nil || !account.Verified {
		service.Notice(rb, client.t("Account does not exist"))
		return
	}

	service.Notice(rb, fmt.Sprintf(client.t("Account: %s"), account.Name))
	registeredAt := account.RegisteredAt.Format(time.RFC1123)
	service.Notice(rb, fmt.Sprintf(client.t("Registered at: %s"), registeredAt))

	if account.Name == client.AccountName() || client.HasRoleCapabs("accreg") {
		if account.Settings.Email != "" {
			service.Notice(rb, fmt.Sprintf(client.t("Email address: %s"), account.Settings.Email))
		}
	}

	// TODO nicer formatting for this
	for _, nick := range account.AdditionalNicks {
		service.Notice(rb, fmt.Sprintf(client.t("Additional grouped nick: %s"), nick))
	}
	listRegisteredChannels(service, accountName, rb)
	if account.Suspended != nil {
		service.Notice(rb, suspensionToString(client, *account.Suspended))
	}
}

func listRegisteredChannels(service *ircService, accountName string, rb *ResponseBuffer) {
	client := rb.session.client
	channels := client.server.accounts.ChannelsForAccount(accountName)
	service.Notice(rb, fmt.Sprintf(client.t("Account %s has %d registered channel(s)."), accountName, len(channels)))
	for _, channel := range rb.session.client.server.accounts.ChannelsForAccount(accountName) {
		service.Notice(rb, fmt.Sprintf(client.t("Registered channel: %s"), channel))
	}
}

func nsRegisterHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	details := client.Details()
	passphrase := params[0]
	var email string
	if 1 < len(params) {
		email = params[1]
	}

	certfp := rb.session.certfp
	if passphrase == "*" {
		if certfp == "" {
			service.Notice(rb, client.t("You must be connected with TLS and a client certificate to do this"))
			return
		} else {
			passphrase = ""
		}
	}

	if passphrase != "" {
		cfPassphrase, err := Casefold(passphrase)
		if err == nil && cfPassphrase == details.nickCasefolded {
			service.Notice(rb, client.t("Usage: REGISTER <passphrase> [email]")) // #1179
			return
		}
	}

	if !nsLoginThrottleCheck(service, client, rb) {
		return
	}

	config := server.Config()
	account := details.nick
	if config.Accounts.NickReservation.ForceGuestFormat {
		matches := config.Accounts.NickReservation.guestRegexp.FindStringSubmatch(account)
		if matches == nil || len(matches) < 2 {
			service.Notice(rb, client.t("Erroneous nickname"))
			return
		}
		account = matches[1]
	}

	callbackNamespace, callbackValue, validationErr := parseCallback(email, config)
	if validationErr != nil {
		service.Notice(rb, client.t("Registration requires a valid e-mail address"))
		return
	}

	err := server.accounts.Register(client, account, callbackNamespace, callbackValue, passphrase, rb.session.certfp)
	if err == nil {
		if callbackNamespace == "*" {
			err = server.accounts.Verify(client, account, "")
			if err == nil && fixupNickEqualsAccount(client, rb, config, service.prefix) {
				sendSuccessfulRegResponse(service, client, rb)
			}
		} else {
			messageTemplate := client.t("Account created, pending verification; verification code has been sent to %s")
			message := fmt.Sprintf(messageTemplate, callbackValue)
			service.Notice(rb, message)
		}
	} else {
		// details could not be stored and relevant numerics have been dispatched, abort
		message := registrationErrorToMessage(config, client, err)
		service.Notice(rb, client.t(message))
	}
}

func nsSaregisterHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	var account, passphrase string
	account = params[0]
	if 1 < len(params) && params[1] != "*" {
		passphrase = params[1]
	}
	err := server.accounts.SARegister(account, passphrase)

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
		service.Notice(rb, errMsg)
	} else {
		service.Notice(rb, fmt.Sprintf(client.t("Successfully registered account %s"), account))
		server.snomasks.Send(sno.LocalAccounts, fmt.Sprintf(ircfmt.Unescape("Operator $c[grey][$r%s$c[grey]] registered account $c[grey][$r%s$c[grey]] with SAREGISTER"), client.Oper().Name, account))
	}
}

func nsUnregisterHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	erase := command == "erase"

	username := params[0]
	var verificationCode string
	if len(params) > 1 {
		verificationCode = params[1]
	}

	if username == "" {
		service.Notice(rb, client.t("You must specify an account"))
		return
	}

	var accountName string
	var registeredAt time.Time
	if erase {
		// account may not be in a loadable state, e.g., if it was unregistered
		accountName = username
		// make the confirmation code nondeterministic for ERASE
		registeredAt = server.ctime
	} else {
		account, err := server.accounts.LoadAccount(username)
		if err == errAccountDoesNotExist {
			service.Notice(rb, client.t("Invalid account name"))
			return
		} else if err != nil {
			service.Notice(rb, client.t("Internal error"))
			return
		}
		accountName = account.Name
		registeredAt = account.RegisteredAt
	}

	if !(accountName == client.AccountName() || client.HasRoleCapabs("accreg")) {
		service.Notice(rb, client.t("Insufficient oper privs"))
		return
	}

	expectedCode := utils.ConfirmationCode(accountName, registeredAt)
	if expectedCode != verificationCode {
		if erase {
			service.Notice(rb, ircfmt.Unescape(client.t("$bWarning: erasing this account will allow it to be re-registered; consider UNREGISTER instead.$b")))
		} else {
			service.Notice(rb, ircfmt.Unescape(client.t("$bWarning: unregistering this account will remove its stored privileges.$b")))
			service.Notice(rb, ircfmt.Unescape(client.t("$bNote that an unregistered account name remains reserved and cannot be re-registered.$b")))
			service.Notice(rb, ircfmt.Unescape(client.t("$bIf you are having problems with your account, contact an administrator.$b")))
		}
		service.Notice(rb, fmt.Sprintf(client.t("To confirm, run this command: %s"), fmt.Sprintf("/NS %s %s %s", strings.ToUpper(command), accountName, expectedCode)))
		return
	}

	err := server.accounts.Unregister(accountName, erase)
	if err == errAccountDoesNotExist {
		service.Notice(rb, client.t(err.Error()))
	} else if err != nil {
		service.Notice(rb, client.t("Error while unregistering account"))
	} else {
		service.Notice(rb, fmt.Sprintf(client.t("Successfully unregistered account %s"), accountName))
		server.logger.Info("accounts", "client", client.Nick(), "unregistered account", accountName)
		client.server.snomasks.Send(sno.LocalAccounts, fmt.Sprintf(ircfmt.Unescape("Client $c[grey][$r%s$c[grey]] unregistered account $c[grey][$r%s$c[grey]]"), client.NickMaskString(), accountName))
	}
}

func nsVerifyHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	username, code := params[0], params[1]
	err := server.accounts.Verify(client, username, code)

	var errorMessage string
	if err != nil {
		switch err {
		case errAccountAlreadyLoggedIn, errAccountVerificationInvalidCode, errAccountAlreadyVerified:
			errorMessage = err.Error()
		default:
			errorMessage = errAccountVerificationFailed.Error()
		}
	}

	if errorMessage != "" {
		service.Notice(rb, client.t(errorMessage))
		return
	}

	if fixupNickEqualsAccount(client, rb, server.Config(), service.prefix) {
		sendSuccessfulRegResponse(service, client, rb)
	}
}

func nsConfirmPassword(server *Server, account, passphrase string) (errorMessage string) {
	accountData, err := server.accounts.LoadAccount(account)
	if err != nil {
		errorMessage = `You're not logged into an account`
	} else {
		hash := accountData.Credentials.PassphraseHash
		if hash != nil {
			if passphrase == "" {
				errorMessage = `You must supply a password`
			} else if passwd.CompareHashAndPassword(hash, []byte(passphrase)) != nil {
				errorMessage = `Password incorrect`
			}
		}
	}
	return
}

func nsPasswdHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	var target string
	var newPassword string
	var errorMessage string

	var oper *Oper

	switch len(params) {
	case 2:
		oper = client.Oper()
		if !oper.HasRoleCapab("accreg") {
			errorMessage = `Insufficient privileges`
		} else {
			target, newPassword = params[0], params[1]
			if newPassword == "*" {
				newPassword = ""
			}
			message := fmt.Sprintf("Operator %s ran NS PASSWD for account %s", oper.Name, target)
			server.snomasks.Send(sno.LocalOpers, message)
			server.logger.Info("opers", message)
		}
	case 3:
		target = client.Account()
		newPassword = params[1]
		if newPassword == "*" {
			newPassword = ""
		}
		if target == "" {
			errorMessage = `You're not logged into an account`
		} else if newPassword != params[2] {
			errorMessage = `Passwords do not match`
		} else {
			if !nsLoginThrottleCheck(service, client, rb) {
				return
			}
			errorMessage = nsConfirmPassword(server, target, params[0])
		}
	default:
		errorMessage = `Invalid parameters`
	}

	if errorMessage != "" {
		service.Notice(rb, client.t(errorMessage))
		return
	}

	err := server.accounts.setPassword(target, newPassword, oper != nil)
	switch err {
	case nil:
		service.Notice(rb, client.t("Password changed"))
	case errEmptyCredentials:
		service.Notice(rb, client.t("You can't delete your password unless you add a certificate fingerprint"))
	case errCredsExternallyManaged:
		service.Notice(rb, client.t("Your account credentials are managed externally and cannot be changed here"))
	case errCASFailed:
		service.Notice(rb, client.t("Try again later"))
	case errAccountDoesNotExist:
		service.Notice(rb, client.t("Account does not exist"))
	default:
		server.logger.Error("internal", "could not upgrade user password:", err.Error())
		service.Notice(rb, client.t("Password could not be changed due to server error"))
	}
}

func nsEnforceHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	newParams := []string{"enforce"}
	if len(params) == 0 {
		nsGetHandler(service, server, client, "get", newParams, rb)
	} else {
		newParams = append(newParams, params[0])
		nsSetHandler(service, server, client, "set", newParams, rb)
	}
}

func nsClientsHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	var verb string

	if command == "sessions" {
		// Legacy "SESSIONS" command is an alias for CLIENTS LIST.
		verb = "list"
	} else if len(params) > 0 {
		verb = strings.ToLower(params[0])
		params = params[1:]
	}

	switch verb {
	case "list":
		nsClientsListHandler(service, server, client, params, rb)
	case "logout":
		nsClientsLogoutHandler(service, server, client, params, rb)
	default:
		service.Notice(rb, client.t("Invalid parameters"))
	}
}

func nsClientsListHandler(service *ircService, server *Server, client *Client, params []string, rb *ResponseBuffer) {
	target := client
	hasPrivs := client.HasRoleCapabs("ban")
	if 0 < len(params) {
		target = server.clients.Get(params[0])
		if target == nil {
			service.Notice(rb, client.t("No such nick"))
			return
		}
		if target != client && !hasPrivs {
			service.Notice(rb, client.t("Command restricted"))
			return
		}
	}

	sessionData, currentIndex := target.AllSessionData(rb.session, hasPrivs)
	service.Notice(rb, fmt.Sprintf(client.t("Nickname %[1]s has %[2]d attached clients(s)"), target.Nick(), len(sessionData)))
	for i, session := range sessionData {
		if currentIndex == i {
			service.Notice(rb, fmt.Sprintf(client.t("Client %d (currently attached client):"), session.sessionID))
		} else {
			service.Notice(rb, fmt.Sprintf(client.t("Client %d:"), session.sessionID))
		}
		if session.deviceID != "" {
			service.Notice(rb, fmt.Sprintf(client.t("Device ID:   %s"), session.deviceID))
		}
		service.Notice(rb, fmt.Sprintf(client.t("IP address:  %s"), session.ip.String()))
		service.Notice(rb, fmt.Sprintf(client.t("Hostname:    %s"), session.hostname))
		if hasPrivs {
			service.Notice(rb, fmt.Sprintf(client.t("Connection:  %s"), session.connInfo))
		}
		service.Notice(rb, fmt.Sprintf(client.t("Created at:  %s"), session.ctime.Format(time.RFC1123)))
		service.Notice(rb, fmt.Sprintf(client.t("Last active: %s"), session.atime.Format(time.RFC1123)))
		if session.certfp != "" {
			service.Notice(rb, fmt.Sprintf(client.t("Certfp:      %s"), session.certfp))
		}
		for _, capStr := range session.caps {
			if capStr != "" {
				service.Notice(rb, fmt.Sprintf(client.t("IRCv3 CAPs:  %s"), capStr))
			}
		}
	}
}

func nsClientsLogoutHandler(service *ircService, server *Server, client *Client, params []string, rb *ResponseBuffer) {
	if len(params) < 1 {
		service.Notice(rb, client.t("Missing client ID to logout (or \"all\")"))
		return
	}

	target := client
	if len(params) >= 2 {
		// CLIENTS LOGOUT [nickname] [client ID]
		target = server.clients.Get(params[0])
		if target == nil {
			service.Notice(rb, client.t("No such nick"))
			return
		}
		// User must have "kill" privileges to logout other user sessions.
		if target != client {
			oper := client.Oper()
			if !oper.HasRoleCapab("kill") {
				service.Notice(rb, client.t("Insufficient oper privs"))
				return
			}
		}
		params = params[1:]
	}

	var sessionToDestroy *Session // target.destroy(nil) will logout all sessions
	if strings.ToLower(params[0]) != "all" {
		sessionID, err := strconv.ParseInt(params[0], 10, 64)
		if err != nil {
			service.Notice(rb, client.t("Client ID to logout should be an integer (or \"all\")"))
			return
		}
		// Find the client ID that the user requested to logout.
		sessions := target.Sessions()
		for _, session := range sessions {
			if session.sessionID == sessionID {
				sessionToDestroy = session
			}
		}
		if sessionToDestroy == nil {
			service.Notice(rb, client.t("Specified client ID does not exist"))
			return
		}
	}

	target.destroy(sessionToDestroy)
	if (sessionToDestroy != nil && rb.session != sessionToDestroy) || client != target {
		if sessionToDestroy != nil {
			service.Notice(rb, client.t("Successfully logged out session"))
		} else {
			service.Notice(rb, client.t("Successfully logged out all sessions"))
		}
	}
}

func nsCertHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	verb := strings.ToLower(params[0])
	params = params[1:]
	var target, certfp string

	switch verb {
	case "list":
		if 1 <= len(params) {
			target = params[0]
		}
	case "add", "del":
		if 2 <= len(params) {
			target, certfp = params[0], params[1]
		} else if len(params) == 1 {
			certfp = params[0]
		} else if len(params) == 0 && verb == "add" && rb.session.certfp != "" {
			certfp = rb.session.certfp // #1059
		} else {
			service.Notice(rb, client.t("Invalid parameters"))
			return
		}
	default:
		service.Notice(rb, client.t("Invalid parameters"))
		return
	}

	hasPrivs := client.HasRoleCapabs("accreg")
	if target != "" && !hasPrivs {
		service.Notice(rb, client.t("Insufficient privileges"))
		return
	} else if target == "" {
		target = client.Account()
		if target == "" {
			service.Notice(rb, client.t("You're not logged into an account"))
			return
		}
	}

	var err error
	switch verb {
	case "list":
		accountData, err := server.accounts.LoadAccount(target)
		if err == errAccountDoesNotExist {
			service.Notice(rb, client.t("Account does not exist"))
			return
		} else if err != nil {
			service.Notice(rb, client.t("An error occurred"))
			return
		}
		certfps := accountData.Credentials.Certfps
		service.Notice(rb, fmt.Sprintf(client.t("There are %[1]d certificate fingerprint(s) authorized for account %[2]s."), len(certfps), accountData.Name))
		for i, certfp := range certfps {
			service.Notice(rb, fmt.Sprintf("%d: %s", i+1, certfp))
		}
		return
	case "add":
		err = server.accounts.addRemoveCertfp(target, certfp, true, hasPrivs)
	case "del":
		err = server.accounts.addRemoveCertfp(target, certfp, false, hasPrivs)
	}

	switch err {
	case nil:
		if verb == "add" {
			service.Notice(rb, client.t("Certificate fingerprint successfully added"))
		} else {
			service.Notice(rb, client.t("Certificate fingerprint successfully removed"))
		}
	case errNoop:
		if verb == "add" {
			service.Notice(rb, client.t("That certificate fingerprint was already authorized"))
		} else {
			service.Notice(rb, client.t("Certificate fingerprint not found"))
		}
	case errAccountDoesNotExist:
		service.Notice(rb, client.t("Account does not exist"))
	case errLimitExceeded:
		service.Notice(rb, client.t("You already have too many certificate fingerprints"))
	case utils.ErrInvalidCertfp:
		service.Notice(rb, client.t("Invalid certificate fingerprint"))
	case errCertfpAlreadyExists:
		service.Notice(rb, client.t("That certificate fingerprint is already associated with another account"))
	case errEmptyCredentials:
		service.Notice(rb, client.t("You can't remove all your certificate fingerprints unless you add a password"))
	case errCredsExternallyManaged:
		service.Notice(rb, client.t("Your account credentials are managed externally and cannot be changed here"))
	case errCASFailed:
		service.Notice(rb, client.t("Try again later"))
	default:
		server.logger.Error("internal", "could not modify certificates:", err.Error())
		service.Notice(rb, client.t("An error occurred"))
	}
}

func nsSuspendHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	subCmd := strings.ToLower(params[0])
	params = params[1:]
	switch subCmd {
	case "add":
		nsSuspendAddHandler(service, server, client, command, params, rb)
	case "del", "delete", "remove":
		nsSuspendRemoveHandler(service, server, client, command, params, rb)
	case "list":
		nsSuspendListHandler(service, server, client, command, params, rb)
	default:
		service.Notice(rb, client.t("Invalid parameters"))
	}
}

func nsSuspendAddHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	if len(params) == 0 {
		service.Notice(rb, client.t("Invalid parameters"))
		return
	}

	account := params[0]
	params = params[1:]

	var duration time.Duration
	if 2 <= len(params) && strings.ToLower(params[0]) == "duration" {
		var err error
		cDuration, err := custime.ParseDuration(params[1])
		if err != nil {
			service.Notice(rb, client.t("Invalid time duration for NS SUSPEND"))
			return
		}
		duration = time.Duration(cDuration)
		params = params[2:]
	}

	var reason string
	if len(params) != 0 {
		reason = strings.Join(params, " ")
	}

	name := client.Oper().Name

	err := server.accounts.Suspend(account, duration, name, reason)
	switch err {
	case nil:
		service.Notice(rb, fmt.Sprintf(client.t("Successfully suspended account %s"), account))
	case errAccountDoesNotExist:
		service.Notice(rb, client.t("No such account"))
	default:
		service.Notice(rb, client.t("An error occurred"))
	}
}

func nsSuspendRemoveHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	if len(params) == 0 {
		service.Notice(rb, client.t("Invalid parameters"))
		return
	}

	err := server.accounts.Unsuspend(params[0])
	switch err {
	case nil:
		service.Notice(rb, fmt.Sprintf(client.t("Successfully un-suspended account %s"), params[0]))
	case errAccountDoesNotExist:
		service.Notice(rb, client.t("No such account"))
	case errNoop:
		service.Notice(rb, client.t("Account was not suspended"))
	default:
		service.Notice(rb, client.t("An error occurred"))
	}
}

// sort in reverse order of creation time
type ByCreationTime []AccountSuspension

func (a ByCreationTime) Len() int           { return len(a) }
func (a ByCreationTime) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByCreationTime) Less(i, j int) bool { return a[i].TimeCreated.After(a[j].TimeCreated) }

func nsSuspendListHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	listAccountSuspensions(client, rb, service.prefix)
}

func listAccountSuspensions(client *Client, rb *ResponseBuffer, source string) {
	suspensions := client.server.accounts.ListSuspended()
	sort.Sort(ByCreationTime(suspensions))
	nick := client.Nick()
	rb.Add(nil, source, "NOTICE", nick, fmt.Sprintf(client.t("There are %d active account suspensions."), len(suspensions)))
	for _, suspension := range suspensions {
		rb.Add(nil, source, "NOTICE", nick, suspensionToString(client, suspension))
	}
}

func suspensionToString(client *Client, suspension AccountSuspension) (result string) {
	duration := client.t("indefinite")
	if suspension.Duration != time.Duration(0) {
		duration = suspension.Duration.String()
	}
	ts := suspension.TimeCreated.Format(time.RFC1123)
	reason := client.t("No reason given.")
	if suspension.Reason != "" {
		reason = fmt.Sprintf(client.t("Reason: %s"), suspension.Reason)
	}
	return fmt.Sprintf(client.t("Account %[1]s suspended at %[2]s. Duration: %[3]s. %[4]s"), suspension.AccountName, ts, duration, reason)
}

func nsSendpassHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	if !nsLoginThrottleCheck(service, client, rb) {
		return
	}

	account := params[0]
	var message string
	err := server.accounts.NsSendpass(client, account)
	switch err {
	case nil:
		server.snomasks.Send(sno.LocalAccounts, fmt.Sprintf("Client %s sent a password reset for account %s", client.Nick(), account))
		message = `Successfully sent password reset email`
	case errAccountDoesNotExist, errAccountUnverified, errAccountSuspended:
		message = err.Error()
	case errValidEmailRequired:
		message = `That account is not associated with an email address`
	case errLimitExceeded:
		message = `Try again later`
	default:
		server.logger.Error("services", "error in NS SENDPASS", err.Error())
		message = `An error occurred`
	}
	rb.Notice(client.t(message))
}

func nsResetpassHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	if !nsLoginThrottleCheck(service, client, rb) {
		return
	}

	var message string
	err := server.accounts.NsResetpass(client, params[0], params[1], params[2])
	switch err {
	case nil:
		message = `Successfully reset account password`
	case errAccountDoesNotExist, errAccountUnverified, errAccountSuspended, errAccountBadPassphrase:
		message = err.Error()
	case errAccountInvalidCredentials:
		message = `Code did not match`
	default:
		server.logger.Error("services", "error in NS RESETPASS", err.Error())
		message = `An error occurred`
	}
	rb.Notice(client.t(message))
}

func nsRenameHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	oldName, newName := params[0], params[1]
	err := server.accounts.Rename(oldName, newName)

	if err != nil {
		service.Notice(rb, fmt.Sprintf(client.t("Couldn't rename account: %s"), client.t(err.Error())))
		return
	}

	service.Notice(rb, client.t("Successfully renamed account"))
	if server.Config().Accounts.NickReservation.ForceNickEqualsAccount {
		if curClient := server.clients.Get(oldName); curClient != nil {
			renameErr := performNickChange(client.server, client, curClient, nil, newName, rb)
			if renameErr != nil && renameErr != errNoop {
				service.Notice(rb, fmt.Sprintf(client.t("Warning: could not rename affected client: %v"), err))
			}
		}
	}
}
