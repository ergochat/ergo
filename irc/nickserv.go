// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"sort"
	"strings"

	"github.com/goshuirc/irc-go/ircfmt"

	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/utils"
)

const nickservHelp = `NickServ lets you register and login to an account.

To see in-depth help for a specific NickServ command, try:
    $b/NS HELP <command>$b

Here are the commands you can use:
%s`

type nsCommand struct {
	capabs          []string // oper capabs the given user has to have to access this command
	handler         func(server *Server, client *Client, command, params string, rb *ResponseBuffer)
	help            string
	helpShort       string
	nickReservation bool // nick reservation must be enabled to use this command
	oper            bool // true if the user has to be an oper to use this command
}

var (
	nickservCommands = map[string]*nsCommand{
		"drop": {
			handler: nsDropHandler,
			help: `Syntax: $bDROP [nickname]$b

DROP de-links the given (or your current) nickname from your user account.`,
			helpShort:       `$bDROP$b de-links your current (or the given) nickname from your user account.`,
			nickReservation: true,
		},
		"ghost": {
			handler: nsGhostHandler,
			help: `Syntax: $bGHOST <nickname>$b

GHOST disconnects the given user from the network if they're logged in with the
same user account, letting you reclaim your nickname.`,
			helpShort: `$bGHOST$b reclaims your nickname.`,
		},
		"group": {
			handler: nsGroupHandler,
			help: `Syntax: $bGROUP$b

GROUP links your current nickname with your logged-in account, preventing other
users from changing to it (or forcing them to rename).`,
			helpShort:       `$bGROUP$b links your current nickname to your user account.`,
			nickReservation: true,
		},
		"help": {
			help: `Syntax: $bHELP [command]$b

HELP returns information on the given command.`,
			helpShort: `$bHELP$b shows in-depth information about commands.`,
		},
		"identify": {
			handler: nsIdentifyHandler,
			help: `Syntax: $bIDENTIFY <username> [password]$b

IDENTIFY lets you login to the given username using either password auth, or
certfp (your client certificate) if a password is not given.`,
			helpShort: `$bIDENTIFY$b lets you login to your account.`,
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
		},
		"sadrop": {
			handler: nsDropHandler,
			help: `Syntax: $bSADROP <nickname>$b

SADROP foribly de-links the given nickname from the attached user account.`,
			helpShort:       `$bSADROP$b forcibly de-links the given nickname from its user account.`,
			nickReservation: true,
			capabs:          []string{"unregister"},
		},
		"unregister": {
			handler: nsUnregisterHandler,
			help: `Syntax: $bUNREGISTER [username]$b

UNREGISTER lets you delete your user account (or the given one, if you're an
IRC operator with the correct permissions).`,
			helpShort: `$bUNREGISTER$b lets you delete your user account.`,
		},
		"verify": {
			handler: nsVerifyHandler,
			help: `Syntax: $bVERIFY <username> <code>$b

VERIFY lets you complete an account registration, if the server requires email
or other verification.`,
			helpShort: `$bVERIFY$b lets you complete account registration.`,
		},
	}
)

// nsNotice sends the client a notice from NickServ
func nsNotice(rb *ResponseBuffer, text string) {
	rb.Add(nil, "NickServ", "NOTICE", rb.target.Nick(), text)
}

// nickservNoticeHandler handles NOTICEs that NickServ receives.
func (server *Server) nickservNoticeHandler(client *Client, message string, rb *ResponseBuffer) {
	// do nothing
}

// nickservPrivmsgHandler handles PRIVMSGs that NickServ receives.
func (server *Server) nickservPrivmsgHandler(client *Client, message string, rb *ResponseBuffer) {
	commandName, params := utils.ExtractParam(message)
	commandName = strings.ToLower(commandName)

	commandInfo := nickservCommands[commandName]
	if commandInfo == nil {
		nsNotice(rb, client.t("Unknown command. To see available commands, run /NS HELP"))
		return
	}

	if commandInfo.oper && !client.HasMode(modes.Operator) {
		nsNotice(rb, client.t("Command restricted"))
		return
	}

	if 0 < len(commandInfo.capabs) && !client.HasRoleCapabs(commandInfo.capabs...) {
		nsNotice(rb, client.t("Command restricted"))
		return
	}

	if commandInfo.nickReservation && !server.AccountConfig().Registration.Enabled {
		nsNotice(rb, client.t("Account registration has been disabled"))
		return
	}

	// custom help handling here to prevent recursive init loop
	if commandName == "help" {
		nsHelpHandler(server, client, commandName, params, rb)
		return
	}

	if commandInfo.handler == nil {
		nsNotice(rb, client.t("Command error. Please report this to the developers"))
		return
	}

	server.logger.Debug("nickserv", fmt.Sprintf("Client %s ran command %s", client.Nick(), commandName))

	commandInfo.handler(server, client, commandName, params, rb)
}

func nsDropHandler(server *Server, client *Client, command, params string, rb *ResponseBuffer) {
	sadrop := command == "sadrop"
	nick, _ := utils.ExtractParam(params)

	err := server.accounts.SetNickReserved(client, nick, sadrop, false)
	if err == nil {
		nsNotice(rb, fmt.Sprintf(client.t("Successfully ungrouped nick %s with your account"), nick))
	} else if err == errAccountNotLoggedIn {
		nsNotice(rb, client.t("You're not logged into an account"))
	} else if err == errAccountCantDropPrimaryNick {
		nsNotice(rb, client.t("You can't ungroup your primary nickname (try unregistering your account instead)"))
	} else if err == errNicknameReserved {
		nsNotice(rb, client.t("That nickname is already reserved by someone else"))
	} else {
		nsNotice(rb, client.t("Could not ungroup nick"))
	}
}

func nsGhostHandler(server *Server, client *Client, command, params string, rb *ResponseBuffer) {
	nick, _ := utils.ExtractParam(params)

	account := client.Account()
	if account == "" || server.accounts.NickToAccount(nick) != account {
		nsNotice(rb, client.t("You don't own that nick"))
		return
	}

	ghost := server.clients.Get(nick)
	if ghost == nil {
		nsNotice(rb, client.t("No such nick"))
		return
	} else if ghost == client {
		nsNotice(rb, client.t("You can't GHOST yourself (try /QUIT instead)"))
		return
	}

	ghost.Quit(fmt.Sprintf(ghost.t("GHOSTed by %s"), client.Nick()))
	ghost.destroy(false)
}

func nsGroupHandler(server *Server, client *Client, command, params string, rb *ResponseBuffer) {
	account := client.Account()
	if account == "" {
		nsNotice(rb, client.t("You're not logged into an account"))
		return
	}

	nick := client.NickCasefolded()
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

func nsHelpHandler(server *Server, client *Client, command, params string, rb *ResponseBuffer) {
	nsNotice(rb, ircfmt.Unescape(client.t("*** $bNickServ HELP$b ***")))

	if params == "" {
		// show general help
		var shownHelpLines sort.StringSlice
		for _, commandInfo := range nickservCommands {
			// skip commands user can't access
			if commandInfo.oper && !client.HasMode(modes.Operator) {
				continue
			}
			if 0 < len(commandInfo.capabs) && !client.HasRoleCapabs(commandInfo.capabs...) {
				continue
			}
			if commandInfo.nickReservation && !server.AccountConfig().Registration.Enabled {
				continue
			}

			shownHelpLines = append(shownHelpLines, "    "+client.t(commandInfo.helpShort))
		}

		// sort help lines
		sort.Sort(shownHelpLines)

		// assemble help text
		assembledHelpLines := strings.Join(shownHelpLines, "\n")
		fullHelp := ircfmt.Unescape(fmt.Sprintf(client.t(nickservHelp), assembledHelpLines))

		// push out help text
		for _, line := range strings.Split(fullHelp, "\n") {
			nsNotice(rb, line)
		}
	} else {
		commandInfo := nickservCommands[strings.ToLower(strings.TrimSpace(params))]
		if commandInfo == nil {
			nsNotice(rb, client.t("Unknown command. To see available commands, run /NS HELP"))
		} else {
			for _, line := range strings.Split(ircfmt.Unescape(client.t(commandInfo.help)), "\n") {
				nsNotice(rb, line)
			}
		}
	}

	nsNotice(rb, ircfmt.Unescape(client.t("*** $bEnd of NickServ HELP$b ***")))
}

func nsIdentifyHandler(server *Server, client *Client, command, params string, rb *ResponseBuffer) {
	// fail out if we need to
	if !server.AccountConfig().AuthenticationEnabled {
		nsNotice(rb, client.t("Login has been disabled"))
		return
	}

	loginSuccessful := false

	username, passphrase := utils.ExtractParam(params)

	// try passphrase
	if username != "" && passphrase != "" {
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

func nsInfoHandler(server *Server, client *Client, command, params string, rb *ResponseBuffer) {
	nick, _ := utils.ExtractParam(params)

	if nick == "" {
		nick = client.Nick()
	}

	accountName := nick
	if server.AccountConfig().NickReservation.Enabled {
		accountName = server.accounts.NickToAccount(nick)
		if accountName == "" {
			nsNotice(rb, client.t("That nickname is not registered"))
			return
		}
	}

	account, err := server.accounts.LoadAccount(accountName)
	if err != nil || !account.Verified {
		nsNotice(rb, client.t("Account does not exist"))
	}

	nsNotice(rb, fmt.Sprintf(client.t("Account: %s"), account.Name))
	registeredAt := account.RegisteredAt.Format("Jan 02, 2006 15:04:05Z")
	nsNotice(rb, fmt.Sprintf(client.t("Registered at: %s"), registeredAt))
	// TODO nicer formatting for this
	for _, nick := range account.AdditionalNicks {
		nsNotice(rb, fmt.Sprintf(client.t("Additional grouped nick: %s"), nick))
	}
}

func nsRegisterHandler(server *Server, client *Client, command, params string, rb *ResponseBuffer) {
	// get params
	username, afterUsername := utils.ExtractParam(params)
	email, passphrase := utils.ExtractParam(afterUsername)

	if !server.AccountConfig().Registration.Enabled {
		nsNotice(rb, client.t("Account registration has been disabled"))
		return
	}

	if username == "" {
		nsNotice(rb, client.t("No username supplied"))
		return
	}

	certfp := client.certfp
	if passphrase == "" && certfp == "" {
		nsNotice(rb, client.t("You need to either supply a passphrase or be connected via TLS with a client cert"))
		return
	}

	if client.LoggedIntoAccount() {
		if server.AccountConfig().Registration.AllowMultiplePerConnection {
			server.accounts.Logout(client)
		} else {
			nsNotice(rb, client.t("You're already logged into an account"))
			return
		}
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

	// get and sanitise account name
	account := strings.TrimSpace(username)

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
		errMsg := client.t("Could not register")
		if err == errCertfpAlreadyExists {
			errMsg = client.t("An account already exists for your certificate fingerprint")
		} else if err == errAccountAlreadyRegistered {
			errMsg = client.t("Account already exists")
		}
		nsNotice(rb, errMsg)
		return
	}
}

func nsUnregisterHandler(server *Server, client *Client, command, params string, rb *ResponseBuffer) {
	username, _ := utils.ExtractParam(params)

	if !server.AccountConfig().Registration.Enabled {
		nsNotice(rb, client.t("Account registration has been disabled"))
		return
	}

	if username == "" {
		username = client.Account()
	}
	if username == "" {
		nsNotice(rb, client.t("You're not logged into an account"))
		return
	}
	cfname, err := CasefoldName(username)
	if err != nil {
		nsNotice(rb, client.t("Invalid username"))
		return
	}
	if !(cfname == client.Account() || client.HasRoleCapabs("unregister")) {
		nsNotice(rb, client.t("Insufficient oper privs"))
		return
	}

	if cfname == client.Account() {
		client.server.accounts.Logout(client)
	}

	err = server.accounts.Unregister(cfname)
	if err == errAccountDoesNotExist {
		nsNotice(rb, client.t(err.Error()))
	} else if err != nil {
		nsNotice(rb, client.t("Error while unregistering account"))
	} else {
		nsNotice(rb, fmt.Sprintf(client.t("Successfully unregistered account %s"), cfname))
	}
}

func nsVerifyHandler(server *Server, client *Client, command, params string, rb *ResponseBuffer) {
	username, code := utils.ExtractParam(params)

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
