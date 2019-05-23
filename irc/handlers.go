// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2018 Daniel Oaks <daniel@danieloaks.net>
// Copyright (c) 2017-2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/goshuirc/irc-go/ircmatch"
	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/oragono/oragono/irc/caps"
	"github.com/oragono/oragono/irc/custime"
	"github.com/oragono/oragono/irc/history"
	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/sno"
	"github.com/oragono/oragono/irc/utils"
	"golang.org/x/crypto/bcrypt"
)

// ACC [LS|REGISTER|VERIFY] ...
func accHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	subcommand := strings.ToLower(msg.Params[0])

	if subcommand == "ls" {
		config := server.Config().Accounts

		rb.Add(nil, server.name, "ACC", "LS", "SUBCOMMANDS", "LS REGISTER VERIFY")

		// this list is sorted by the config loader, yay
		rb.Add(nil, server.name, "ACC", "LS", "CALLBACKS", strings.Join(config.Registration.EnabledCallbacks, " "))

		rb.Add(nil, server.name, "ACC", "LS", "CREDTYPES", "passphrase certfp")

		flags := []string{"nospaces"}
		if config.NickReservation.Enabled {
			flags = append(flags, "regnick")
		}
		sort.Strings(flags)
		rb.Add(nil, server.name, "ACC", "LS", "FLAGS", strings.Join(flags, " "))
		return false
	}

	// disallow account stuff before connection registration has completed, for now
	if !client.Registered() {
		client.Send(nil, server.name, ERR_NOTREGISTERED, "*", client.t("You need to register before you can use that command"))
		return false
	}

	// make sure reg is enabled
	if !server.AccountConfig().Registration.Enabled {
		rb.Add(nil, server.name, "FAIL", "ACC", "REG_UNAVAILABLE", client.t("Account registration is disabled"))
		return false
	}

	if subcommand == "register" {
		return accRegisterHandler(server, client, msg, rb)
	} else if subcommand == "verify" {
		return accVerifyHandler(server, client, msg, rb)
	} else {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.nick, "ACC", msg.Params[0], client.t("Unknown subcommand"))
	}

	return false
}

// helper function to parse ACC callbacks, e.g., mailto:person@example.com, tel:16505551234
func parseCallback(spec string, config *AccountConfig) (callbackNamespace string, callbackValue string) {
	callback := strings.ToLower(spec)
	if callback == "*" {
		callbackNamespace = "*"
	} else if strings.Contains(callback, ":") {
		callbackValues := strings.SplitN(callback, ":", 2)
		callbackNamespace, callbackValue = callbackValues[0], callbackValues[1]
	} else {
		// "If a callback namespace is not ... provided, the IRC server MUST use mailto""
		callbackNamespace = "mailto"
		callbackValue = callback
	}

	// ensure the callback namespace is valid
	// need to search callback list, maybe look at using a map later?
	for _, name := range config.Registration.EnabledCallbacks {
		if callbackNamespace == name {
			return
		}
	}
	// error value
	callbackNamespace = ""
	return
}

// ACC REGISTER <accountname> [callback_namespace:]<callback> [cred_type] :<credential>
func accRegisterHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	nick := client.Nick()

	if len(msg.Params) < 4 {
		rb.Add(nil, server.name, ERR_NEEDMOREPARAMS, nick, msg.Command, client.t("Not enough parameters"))
		return false
	}

	account := msg.Params[1]

	// check for account name of *
	if account == "*" {
		account = nick
	} else {
		if server.Config().Accounts.NickReservation.Enabled {
			rb.Add(nil, server.name, "FAIL", "ACC", "REG_MUST_USE_REGNICK", account, client.t("Must register with current nickname instead of separate account name"))
			return false
		}
	}

	// clients can't reg new accounts if they're already logged in
	if client.LoggedIntoAccount() {
		rb.Add(nil, server.name, "FAIL", "ACC", "REG_UNSPECIFIED_ERROR", account, client.t("You're already logged into an account"))
		return false
	}

	// sanitise account name
	casefoldedAccount, err := CasefoldName(account)
	if err != nil {
		rb.Add(nil, server.name, "FAIL", "ACC", "REG_INVALID_ACCOUNT_NAME", account, client.t("Account name is not valid"))
		return false
	}

	callbackSpec := msg.Params[2]
	callbackNamespace, callbackValue := parseCallback(callbackSpec, server.AccountConfig())

	if callbackNamespace == "" {
		rb.Add(nil, server.name, "FAIL", "ACC", "REG_INVALID_CALLBACK", account, callbackSpec, client.t("Cannot send verification code there"))
		return false
	}

	// get credential type/value
	var credentialType, credentialValue string

	if len(msg.Params) > 4 {
		credentialType = strings.ToLower(msg.Params[3])
		credentialValue = msg.Params[4]
	} else {
		// exactly 4 params
		credentialType = "passphrase" // default from the spec
		credentialValue = msg.Params[3]
	}

	// ensure the credential type is valid
	var credentialValid bool
	for _, name := range server.AccountConfig().Registration.EnabledCredentialTypes {
		if credentialType == name {
			credentialValid = true
		}
	}
	if credentialType == "certfp" && client.certfp == "" {
		rb.Add(nil, server.name, "FAIL", "ACC", "REG_INVALID_CREDENTIAL", account, client.t("You must connect with a TLS client certificate to use certfp"))
		return false
	}

	if !credentialValid {
		rb.Add(nil, server.name, "FAIL", "ACC", "REG_INVALID_CRED_TYPE", account, credentialType, client.t("Credential type is not supported"))
		return false
	}

	var passphrase, certfp string
	if credentialType == "certfp" {
		certfp = client.certfp
	} else if credentialType == "passphrase" {
		passphrase = credentialValue
	}

	throttled, remainingTime := client.loginThrottle.Touch()
	if throttled {
		rb.Add(nil, server.name, "FAIL", "ACC", "REG_UNSPECIFIED_ERROR", account, fmt.Sprintf(client.t("Please wait at least %v and try again"), remainingTime))
		return false
	}

	err = server.accounts.Register(client, account, callbackNamespace, callbackValue, passphrase, certfp)
	if err != nil {
		msg, code := registrationErrorToMessageAndCode(err)
		rb.Add(nil, server.name, "FAIL", "ACC", code, account, client.t(msg))
		return false
	}

	// automatically complete registration
	if callbackNamespace == "*" {
		err := server.accounts.Verify(client, casefoldedAccount, "")
		if err != nil {
			return false
		}
		sendSuccessfulRegResponse(client, rb, false)
	} else {
		messageTemplate := client.t("Account created, pending verification; verification code has been sent to %s")
		message := fmt.Sprintf(messageTemplate, fmt.Sprintf("%s:%s", callbackNamespace, callbackValue))
		rb.Add(nil, server.name, RPL_REG_VERIFICATION_REQUIRED, nick, casefoldedAccount, message)
	}

	return false
}

func registrationErrorToMessageAndCode(err error) (message, code string) {
	// default responses: let's be risk-averse about displaying internal errors
	// to the clients, especially for something as sensitive as accounts
	code = "REG_UNSPECIFIED_ERROR"
	message = `Could not register`
	switch err {
	case errAccountBadPassphrase:
		code = "REG_INVALID_CREDENTIAL"
		message = err.Error()
	case errAccountAlreadyRegistered, errAccountAlreadyVerified:
		message = err.Error()
	case errAccountCreation, errAccountMustHoldNick, errAccountBadPassphrase, errCertfpAlreadyExists, errFeatureDisabled:
		message = err.Error()
	}
	return
}

// helper function to dispatch messages when a client successfully registers
func sendSuccessfulRegResponse(client *Client, rb *ResponseBuffer, forNS bool) {
	if forNS {
		rb.Notice(client.t("Account created"))
	} else {
		rb.Add(nil, client.server.name, RPL_REG_SUCCESS, client.nick, client.AccountName(), client.t("Account created"))
	}
	sendSuccessfulAccountAuth(client, rb, forNS, false)
}

// sendSuccessfulAccountAuth means that an account auth attempt completed successfully, and is used to dispatch messages.
func sendSuccessfulAccountAuth(client *Client, rb *ResponseBuffer, forNS, forSASL bool) {
	details := client.Details()

	if forNS {
		rb.Notice(fmt.Sprintf(client.t("You're now logged in as %s"), details.accountName))
	} else {
		//TODO(dan): some servers send this numeric even for NickServ logins iirc? to confirm and maybe do too
		rb.Add(nil, client.server.name, RPL_LOGGEDIN, details.nick, details.nickMask, details.accountName, fmt.Sprintf(client.t("You are now logged in as %s"), details.accountName))
		if forSASL {
			rb.Add(nil, client.server.name, RPL_SASLSUCCESS, details.nick, client.t("Authentication successful"))
		}
	}

	// dispatch account-notify
	for friend := range client.Friends(caps.AccountNotify) {
		friend.Send(nil, details.nickMask, "ACCOUNT", details.accountName)
	}

	client.server.snomasks.Send(sno.LocalAccounts, fmt.Sprintf(ircfmt.Unescape("Client $c[grey][$r%s$c[grey]] logged into account $c[grey][$r%s$c[grey]]"), details.nickMask, details.accountName))

	client.server.logger.Info("accounts", "client", details.nick, "logged into account", details.accountName)
}

// ACC VERIFY <accountname> <auth_code>
func accVerifyHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	account := strings.TrimSpace(msg.Params[1])

	if len(msg.Params) < 3 {
		rb.Add(nil, server.name, ERR_NEEDMOREPARAMS, client.Nick(), msg.Command, client.t("Not enough parameters"))
		return false
	}

	err := server.accounts.Verify(client, account, msg.Params[2])

	var code string
	var message string

	if err == errAccountVerificationInvalidCode {
		code = "ACCOUNT_INVALID_VERIFY_CODE"
		message = err.Error()
	} else if err == errAccountAlreadyVerified {
		code = "ACCOUNT_ALREADY_VERIFIED"
		message = err.Error()
	} else if err != nil {
		code = "VERIFY_UNSPECIFIED_ERROR"
		message = errAccountVerificationFailed.Error()
	}

	if err == nil {
		rb.Add(nil, server.name, RPL_VERIFY_SUCCESS, client.Nick(), account, client.t("Account verification successful"))
		sendSuccessfulAccountAuth(client, rb, false, false)
	} else {
		rb.Add(nil, server.name, "FAIL", "ACC", code, account, client.t(message))
	}

	return false
}

// AUTHENTICATE [<mechanism>|<data>|*]
func authenticateHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	config := server.Config()
	details := client.Details()

	if details.account != "" {
		rb.Add(nil, server.name, ERR_SASLALREADY, details.nick, client.t("You're already logged into an account"))
		return false
	}

	// sasl abort
	if !server.AccountConfig().AuthenticationEnabled || len(msg.Params) == 1 && msg.Params[0] == "*" {
		rb.Add(nil, server.name, ERR_SASLABORTED, details.nick, client.t("SASL authentication aborted"))
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
			if !config.Server.Compatibility.SendUnprefixedSasl {
				// normal behavior
				rb.Add(nil, server.name, "AUTHENTICATE", "+")
			} else {
				// gross hack: send a raw message to ensure no tags or prefix
				rb.Flush(true)
				rb.session.SendRawMessage(ircmsg.MakeMessage(nil, "", "AUTHENTICATE", "+"), true)
			}
		} else {
			rb.Add(nil, server.name, ERR_SASLFAIL, details.nick, client.t("SASL authentication failed"))
		}

		return false
	}

	// continue existing sasl session
	rawData := msg.Params[0]

	if len(rawData) > 400 {
		rb.Add(nil, server.name, ERR_SASLTOOLONG, details.nick, client.t("SASL message too long"))
		client.saslInProgress = false
		client.saslMechanism = ""
		client.saslValue = ""
		return false
	} else if len(rawData) == 400 {
		client.saslValue += rawData
		// allow 4 'continuation' lines before rejecting for length
		if len(client.saslValue) > 400*4 {
			rb.Add(nil, server.name, ERR_SASLFAIL, details.nick, client.t("SASL authentication failed: Passphrase too long"))
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
			rb.Add(nil, server.name, ERR_SASLFAIL, details.nick, client.t("SASL authentication failed: Invalid b64 encoding"))
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
		rb.Add(nil, server.name, ERR_SASLFAIL, details.nick, client.t("SASL authentication failed"))
		client.saslInProgress = false
		client.saslMechanism = ""
		client.saslValue = ""
		return false
	}

	// let the SASL handler do its thing
	exiting := handler(server, client, client.saslMechanism, data, rb)

	// wait 'til SASL is done before emptying the sasl vars
	client.saslInProgress = false
	client.saslMechanism = ""
	client.saslValue = ""

	return exiting
}

// AUTHENTICATE PLAIN
func authPlainHandler(server *Server, client *Client, mechanism string, value []byte, rb *ResponseBuffer) bool {
	splitValue := bytes.Split(value, []byte{'\000'})

	var accountKey, authzid string

	nick := client.Nick()

	if len(splitValue) == 3 {
		accountKey = string(splitValue[0])
		authzid = string(splitValue[1])

		if accountKey == "" {
			accountKey = authzid
		} else if accountKey != authzid {
			rb.Add(nil, server.name, ERR_SASLFAIL, nick, client.t("SASL authentication failed: authcid and authzid should be the same"))
			return false
		}
	} else {
		rb.Add(nil, server.name, ERR_SASLFAIL, nick, client.t("SASL authentication failed: Invalid auth blob"))
		return false
	}

	throttled, remainingTime := client.loginThrottle.Touch()
	if throttled {
		rb.Add(nil, server.name, ERR_SASLFAIL, nick, fmt.Sprintf(client.t("Please wait at least %v and try again"), remainingTime))
		return false
	}

	password := string(splitValue[2])
	err := server.accounts.AuthenticateByPassphrase(client, accountKey, password)
	if err != nil {
		msg := authErrorToMessage(server, err)
		rb.Add(nil, server.name, ERR_SASLFAIL, nick, fmt.Sprintf("%s: %s", client.t("SASL authentication failed"), client.t(msg)))
		return false
	}

	sendSuccessfulAccountAuth(client, rb, false, true)
	return false
}

func authErrorToMessage(server *Server, err error) (msg string) {
	if err == errAccountDoesNotExist || err == errAccountUnverified || err == errAccountInvalidCredentials {
		msg = err.Error()
	} else {
		server.logger.Error("internal", "sasl authentication failure", err.Error())
		msg = "Unknown"
	}
	return
}

// AUTHENTICATE EXTERNAL
func authExternalHandler(server *Server, client *Client, mechanism string, value []byte, rb *ResponseBuffer) bool {
	if client.certfp == "" {
		rb.Add(nil, server.name, ERR_SASLFAIL, client.nick, client.t("SASL authentication failed, you are not connecting with a certificate"))
		return false
	}

	err := server.accounts.AuthenticateByCertFP(client)
	if err != nil {
		msg := authErrorToMessage(server, err)
		rb.Add(nil, server.name, ERR_SASLFAIL, client.nick, fmt.Sprintf("%s: %s", client.t("SASL authentication failed"), client.t(msg)))
		return false
	}

	sendSuccessfulAccountAuth(client, rb, false, true)
	return false
}

// AWAY [<message>]
func awayHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	var isAway bool
	var awayMessage string
	if len(msg.Params) > 0 {
		isAway = true
		awayMessage = msg.Params[0]
		awayLen := server.Limits().AwayLen
		if len(awayMessage) > awayLen {
			awayMessage = awayMessage[:awayLen]
		}
	}

	client.SetAway(isAway, awayMessage)

	if isAway {
		rb.Add(nil, server.name, RPL_NOWAWAY, client.nick, client.t("You have been marked as being away"))
	} else {
		rb.Add(nil, server.name, RPL_UNAWAY, client.nick, client.t("You are no longer marked as being away"))
	}

	// dispatch away-notify
	details := client.Details()
	for session := range client.Friends(caps.AwayNotify) {
		if isAway {
			session.sendFromClientInternal(false, time.Time{}, "", details.nickMask, details.account, nil, "AWAY", awayMessage)
		} else {
			session.sendFromClientInternal(false, time.Time{}, "", details.nickMask, details.account, nil, "AWAY")
		}
	}

	return false
}

// CAP <subcmd> [<caps>]
func capHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	subCommand := strings.ToUpper(msg.Params[0])
	toAdd := caps.NewSet()
	toRemove := caps.NewSet()
	var capString string

	badCaps := false
	if len(msg.Params) > 1 {
		capString = msg.Params[1]
		strs := strings.Fields(capString)
		for _, str := range strs {
			remove := false
			if str[0] == '-' {
				str = str[1:]
				remove = true
			}
			capab, err := caps.NameToCapability(str)
			if err != nil || (!remove && !SupportedCapabilities.Has(capab)) {
				badCaps = true
			} else if !remove {
				toAdd.Enable(capab)
			} else {
				toRemove.Enable(capab)
			}
		}
	}

	switch subCommand {
	case "LS":
		if !client.registered {
			rb.session.capState = caps.NegotiatingState
		}
		if 1 < len(msg.Params) {
			num, err := strconv.Atoi(msg.Params[1])
			newVersion := caps.Version(num)
			if err == nil && rb.session.capVersion < newVersion {
				rb.session.capVersion = newVersion
			}
		}
		// weechat 1.4 has a bug here where it won't accept the CAP reply unless it contains
		// the server.name source... otherwise it doesn't respond to the CAP message with
		// anything and just hangs on connection.
		//TODO(dan): limit number of caps and send it multiline in 3.2 style as appropriate.
		rb.Add(nil, server.name, "CAP", client.nick, subCommand, SupportedCapabilities.String(rb.session.capVersion, CapValues))

	case "LIST":
		rb.Add(nil, server.name, "CAP", client.nick, subCommand, rb.session.capabilities.String(caps.Cap301, CapValues)) // values not sent on LIST so force 3.1

	case "REQ":
		if !client.registered {
			rb.session.capState = caps.NegotiatingState
		}

		// make sure all capabilities actually exist
		if badCaps {
			rb.Add(nil, server.name, "CAP", client.nick, "NAK", capString)
			return false
		}
		rb.session.capabilities.Union(toAdd)
		rb.session.capabilities.Subtract(toRemove)
		rb.Add(nil, server.name, "CAP", client.nick, "ACK", capString)

		// if this is the first time the client is requesting a resume token,
		// send it to them
		if toAdd.Has(caps.Resume) {
			token := server.resumeManager.GenerateToken(client)
			if token != "" {
				rb.Add(nil, server.name, "RESUME", "TOKEN", token)
			}
		}

		// #511: oragono.io/killme is a fake cap to trap bad clients who blindly request
		// every offered capability:
		if toAdd.Has(caps.KillMe) {
			client.Quit(client.t("Requesting the oragono.io/killme CAP is forbidden"), rb.session)
			return true
		}

		// update maxlenrest, just in case they altered the maxline cap
		rb.session.SetMaxlenRest()

	case "END":
		if !client.registered {
			rb.session.capState = caps.NegotiatedState
		}

	default:
		rb.Add(nil, server.name, ERR_INVALIDCAPCMD, client.nick, subCommand, client.t("Invalid CAP subcommand"))
	}
	return false
}

// CHATHISTORY <target> <preposition> <query> [<limit>]
// e.g., CHATHISTORY #ircv3 AFTER id=ytNBbt565yt4r3err3 10
// CHATHISTORY <target> BETWEEN <query> <query> <direction> [<limit>]
// e.g., CHATHISTORY #ircv3 BETWEEN timestamp=YYYY-MM-DDThh:mm:ss.sssZ timestamp=YYYY-MM-DDThh:mm:ss.sssZ + 100
func chathistoryHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) (exiting bool) {
	config := server.Config()

	var items []history.Item
	success := false
	var hist *history.Buffer
	var channel *Channel
	defer func() {
		// successful responses are sent as a chathistory or history batch
		if success && 0 < len(items) {
			batchType := "chathistory"
			if rb.session.capabilities.Has(caps.EventPlayback) {
				batchType = "history"
			}
			rb.ForceBatchStart(batchType, true)
			if channel == nil {
				client.replayPrivmsgHistory(rb, items, true)
			} else {
				channel.replayHistoryItems(rb, items, false)
			}
			return
		}

		// errors are sent either without a batch, or in a draft/labeled-response batch as usual
		// TODO: send `WARN CHATHISTORY MAX_MESSAGES_EXCEEDED` when appropriate
		if hist == nil {
			rb.Add(nil, server.name, "ERR", "CHATHISTORY", "NO_SUCH_CHANNEL")
		} else if len(items) == 0 {
			rb.Add(nil, server.name, "ERR", "CHATHISTORY", "NO_TEXT_TO_SEND")
		} else if !success {
			rb.Add(nil, server.name, "ERR", "CHATHISTORY", "NEED_MORE_PARAMS")
		}
	}()

	target := msg.Params[0]
	channel = server.channels.Get(target)
	if channel != nil && channel.hasClient(client) {
		// "If [...] the user does not have permission to view the requested content, [...]
		// NO_SUCH_CHANNEL SHOULD be returned"
		hist = &channel.history
	} else {
		targetClient := server.clients.Get(target)
		if targetClient != nil {
			myAccount := client.Account()
			targetAccount := targetClient.Account()
			if myAccount != "" && targetAccount != "" && myAccount == targetAccount {
				hist = targetClient.history
			}
		}
	}
	if hist == nil {
		return
	}

	preposition := strings.ToLower(msg.Params[1])

	parseQueryParam := func(param string) (msgid string, timestamp time.Time, err error) {
		err = errInvalidParams
		pieces := strings.SplitN(param, "=", 2)
		if len(pieces) < 2 {
			return
		}
		identifier, value := strings.ToLower(pieces[0]), pieces[1]
		if identifier == "id" {
			msgid, err = value, nil
			return
		} else if identifier == "timestamp" {
			timestamp, err = time.Parse(IRCv3TimestampFormat, value)
			return
		}
		return
	}

	maxChathistoryLimit := config.History.ChathistoryMax
	if maxChathistoryLimit == 0 {
		return
	}
	parseHistoryLimit := func(paramIndex int) (limit int) {
		if len(msg.Params) < (paramIndex + 1) {
			return maxChathistoryLimit
		}
		limit, err := strconv.Atoi(msg.Params[paramIndex])
		if err != nil || limit == 0 || limit > maxChathistoryLimit {
			limit = maxChathistoryLimit
		}
		return
	}

	// TODO: as currently implemented, almost all of thes queries are worst-case O(n)
	// in the number of stored history entries. Every one of them can be made O(1)
	// if necessary, without too much difficulty. Some ideas:
	// * Ensure that the ring buffer is sorted by time, enabling binary search for times
	// * Maintain a map from msgid to position in the ring buffer

	if preposition == "between" {
		if len(msg.Params) >= 5 {
			startMsgid, startTimestamp, startErr := parseQueryParam(msg.Params[2])
			endMsgid, endTimestamp, endErr := parseQueryParam(msg.Params[3])
			ascending := msg.Params[4] == "+"
			limit := parseHistoryLimit(5)
			if startErr != nil || endErr != nil {
				success = false
			} else if startMsgid != "" && endMsgid != "" {
				inInterval := false
				matches := func(item history.Item) (result bool) {
					result = inInterval
					if item.HasMsgid(startMsgid) {
						if ascending {
							inInterval = true
						} else {
							inInterval = false
							return false // interval is exclusive
						}
					} else if item.HasMsgid(endMsgid) {
						if ascending {
							inInterval = false
							return false
						} else {
							inInterval = true
						}
					}
					return
				}
				items = hist.Match(matches, ascending, limit)
				success = true
			} else if !startTimestamp.IsZero() && !endTimestamp.IsZero() {
				items, _ = hist.Between(startTimestamp, endTimestamp, ascending, limit)
				if !ascending {
					history.Reverse(items)
				}
				success = true
			}
			// else: mismatched params, success = false, fail
		}
		return
	}

	// before, after, latest, around
	queryParam := msg.Params[2]
	msgid, timestamp, err := parseQueryParam(queryParam)
	limit := parseHistoryLimit(3)
	before := false
	switch preposition {
	case "before":
		before = true
		fallthrough
	case "after":
		var matches history.Predicate
		if err != nil {
			break
		} else if msgid != "" {
			inInterval := false
			matches = func(item history.Item) (result bool) {
				result = inInterval
				if item.HasMsgid(msgid) {
					inInterval = true
				}
				return
			}
		} else {
			matches = func(item history.Item) bool {
				return before == item.Message.Time.Before(timestamp)
			}
		}
		items = hist.Match(matches, !before, limit)
		success = true
	case "latest":
		if queryParam == "*" {
			items = hist.Latest(limit)
		} else if err != nil {
			break
		} else {
			var matches history.Predicate
			if msgid != "" {
				shouldStop := false
				matches = func(item history.Item) bool {
					if shouldStop {
						return false
					}
					shouldStop = item.HasMsgid(msgid)
					return !shouldStop
				}
			} else {
				matches = func(item history.Item) bool {
					return item.Message.Time.After(timestamp)
				}
			}
			items = hist.Match(matches, false, limit)
		}
		success = true
	case "around":
		if err != nil {
			break
		}
		var initialMatcher history.Predicate
		if msgid != "" {
			inInterval := false
			initialMatcher = func(item history.Item) (result bool) {
				if inInterval {
					return true
				} else {
					inInterval = item.HasMsgid(msgid)
					return inInterval
				}
			}
		} else {
			initialMatcher = func(item history.Item) (result bool) {
				return item.Message.Time.Before(timestamp)
			}
		}
		var halfLimit int
		halfLimit = (limit + 1) / 2
		firstPass := hist.Match(initialMatcher, false, halfLimit)
		if len(firstPass) > 0 {
			timeWindowStart := firstPass[0].Message.Time
			items = hist.Match(func(item history.Item) bool {
				return item.Message.Time.Equal(timeWindowStart) || item.Message.Time.After(timeWindowStart)
			}, true, limit)
		}
		success = true
	}

	return
}

// DEBUG <subcmd>
func debugHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	param := strings.ToUpper(msg.Params[0])

	switch param {
	case "GCSTATS":
		stats := debug.GCStats{
			Pause:          make([]time.Duration, 10),
			PauseQuantiles: make([]time.Duration, 5),
		}
		debug.ReadGCStats(&stats)

		rb.Notice(fmt.Sprintf("last GC:     %s", stats.LastGC.Format(time.RFC1123)))
		rb.Notice(fmt.Sprintf("num GC:      %d", stats.NumGC))
		rb.Notice(fmt.Sprintf("pause total: %s", stats.PauseTotal))
		rb.Notice(fmt.Sprintf("pause quantiles min%%: %s", stats.PauseQuantiles[0]))
		rb.Notice(fmt.Sprintf("pause quantiles 25%%:  %s", stats.PauseQuantiles[1]))
		rb.Notice(fmt.Sprintf("pause quantiles 50%%:  %s", stats.PauseQuantiles[2]))
		rb.Notice(fmt.Sprintf("pause quantiles 75%%:  %s", stats.PauseQuantiles[3]))
		rb.Notice(fmt.Sprintf("pause quantiles max%%: %s", stats.PauseQuantiles[4]))

	case "NUMGOROUTINE":
		count := runtime.NumGoroutine()
		rb.Notice(fmt.Sprintf("num goroutines: %d", count))

	case "PROFILEHEAP":
		profFile := "oragono.mprof"
		file, err := os.Create(profFile)
		if err != nil {
			rb.Notice(fmt.Sprintf("error: %s", err))
			break
		}
		defer file.Close()
		pprof.Lookup("heap").WriteTo(file, 0)
		rb.Notice(fmt.Sprintf("written to %s", profFile))

	case "STARTCPUPROFILE":
		profFile := "oragono.prof"
		file, err := os.Create(profFile)
		if err != nil {
			rb.Notice(fmt.Sprintf("error: %s", err))
			break
		}
		if err := pprof.StartCPUProfile(file); err != nil {
			defer file.Close()
			rb.Notice(fmt.Sprintf("error: %s", err))
			break
		}

		rb.Notice(fmt.Sprintf("CPU profile writing to %s", profFile))

	case "STOPCPUPROFILE":
		pprof.StopCPUProfile()
		rb.Notice(fmt.Sprintf("CPU profiling stopped"))
	}
	return false
}

// helper for parsing the reason args to DLINE and KLINE
func getReasonsFromParams(params []string, currentArg int) (reason, operReason string) {
	reason = "No reason given"
	operReason = ""
	if len(params) > currentArg {
		reasons := strings.SplitN(strings.Join(params[currentArg:], " "), "|", 2)
		if len(reasons) == 1 {
			reason = strings.TrimSpace(reasons[0])
		} else if len(reasons) == 2 {
			reason = strings.TrimSpace(reasons[0])
			operReason = strings.TrimSpace(reasons[1])
		}
	}
	return
}

func formatBanForListing(client *Client, key string, info IPBanInfo) string {
	desc := info.Reason
	if info.OperReason != "" && info.OperReason != info.Reason {
		desc = fmt.Sprintf("%s | %s", info.Reason, info.OperReason)
	}
	if info.Duration != 0 {
		desc = fmt.Sprintf("%s [%s]", desc, info.TimeLeft())
	}
	return fmt.Sprintf(client.t("Ban - %[1]s - added by %[2]s - %[3]s"), key, info.OperName, desc)
}

// DLINE [ANDKILL] [MYSELF] [duration] <ip>/<net> [ON <server>] [reason [| oper reason]]
// DLINE LIST
func dlineHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	// check oper permissions
	oper := client.Oper()
	if oper == nil || !oper.Class.Capabilities["oper:local_ban"] {
		rb.Add(nil, server.name, ERR_NOPRIVS, client.nick, msg.Command, client.t("Insufficient oper privs"))
		return false
	}

	currentArg := 0

	// if they say LIST, we just list the current dlines
	if len(msg.Params) == currentArg+1 && strings.ToLower(msg.Params[currentArg]) == "list" {
		bans := server.dlines.AllBans()

		if len(bans) == 0 {
			rb.Notice(client.t("No DLINEs have been set!"))
		}

		for key, info := range bans {
			client.Notice(formatBanForListing(client, key, info))
		}

		return false
	}

	// when setting a ban, if they say "ANDKILL" we should also kill all users who match it
	var andKill bool
	if len(msg.Params) > currentArg+1 && strings.ToLower(msg.Params[currentArg]) == "andkill" {
		andKill = true
		currentArg++
	}

	// when setting a ban that covers the oper's current connection, we require them to say
	// "DLINE MYSELF" so that we're sure they really mean it.
	var dlineMyself bool
	if len(msg.Params) > currentArg+1 && strings.ToLower(msg.Params[currentArg]) == "myself" {
		dlineMyself = true
		currentArg++
	}

	// duration
	duration, err := custime.ParseDuration(msg.Params[currentArg])
	if err != nil {
		duration = 0
	} else {
		currentArg++
	}

	// get host
	if len(msg.Params) < currentArg+1 {
		rb.Add(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, msg.Command, client.t("Not enough parameters"))
		return false
	}
	hostString := msg.Params[currentArg]
	currentArg++

	// check host
	hostNet, err := utils.NormalizedNetFromString(hostString)

	if err != nil {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("Could not parse IP address or CIDR network"))
		return false
	}

	if !dlineMyself && hostNet.Contains(client.IP()) {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("This ban matches you. To DLINE yourself, you must use the command:  /DLINE MYSELF <arguments>"))
		return false
	}

	// check remote
	if len(msg.Params) > currentArg && msg.Params[currentArg] == "ON" {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("Remote servers not yet supported"))
		return false
	}

	// get comment(s)
	reason, operReason := getReasonsFromParams(msg.Params, currentArg)

	operName := oper.Name
	if operName == "" {
		operName = server.name
	}

	err = server.dlines.AddNetwork(hostNet, duration, reason, operReason, operName)

	if err != nil {
		rb.Notice(fmt.Sprintf(client.t("Could not successfully save new D-LINE: %s"), err.Error()))
		return false
	}

	var snoDescription string
	hostString = utils.NetToNormalizedString(hostNet)
	if duration != 0 {
		rb.Notice(fmt.Sprintf(client.t("Added temporary (%[1]s) D-Line for %[2]s"), duration.String(), hostString))
		snoDescription = fmt.Sprintf(ircfmt.Unescape("%s [%s]$r added temporary (%s) D-Line for %s"), client.nick, operName, duration.String(), hostString)
	} else {
		rb.Notice(fmt.Sprintf(client.t("Added D-Line for %s"), hostString))
		snoDescription = fmt.Sprintf(ircfmt.Unescape("%s [%s]$r added D-Line for %s"), client.nick, operName, hostString)
	}
	server.snomasks.Send(sno.LocalXline, snoDescription)

	var killClient bool
	if andKill {
		var clientsToKill []*Client
		var killedClientNicks []string

		for _, mcl := range server.clients.AllClients() {
			if hostNet.Contains(mcl.IP()) {
				clientsToKill = append(clientsToKill, mcl)
				killedClientNicks = append(killedClientNicks, mcl.nick)
			}
		}

		for _, mcl := range clientsToKill {
			mcl.exitedSnomaskSent = true
			mcl.Quit(fmt.Sprintf(mcl.t("You have been banned from this server (%s)"), reason), nil)
			if mcl == client {
				killClient = true
			} else {
				// if mcl == client, we kill them below
				mcl.destroy(false, nil)
			}
		}

		// send snomask
		sort.Strings(killedClientNicks)
		server.snomasks.Send(sno.LocalKills, fmt.Sprintf(ircfmt.Unescape("%s [%s] killed %d clients with a DLINE $c[grey][$r%s$c[grey]]"), client.nick, operName, len(killedClientNicks), strings.Join(killedClientNicks, ", ")))
	}

	return killClient
}

// HELP [<query>]
func helpHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	argument := strings.ToLower(strings.TrimSpace(strings.Join(msg.Params, " ")))

	if len(argument) < 1 {
		client.sendHelp("HELPOP", client.t(`HELPOP <argument>

Get an explanation of <argument>, or "index" for a list of help topics.`), rb)
		return false
	}

	// handle index
	if argument == "index" {
		client.sendHelp("HELP", server.helpIndexManager.GetIndex(client.Languages(), client.HasMode(modes.Operator)), rb)
		return false
	}

	helpHandler, exists := Help[argument]

	if exists && (!helpHandler.oper || (helpHandler.oper && client.HasMode(modes.Operator))) {
		if helpHandler.textGenerator != nil {
			client.sendHelp(strings.ToUpper(argument), client.t(helpHandler.textGenerator(client)), rb)
		} else {
			client.sendHelp(strings.ToUpper(argument), client.t(helpHandler.text), rb)
		}
	} else {
		args := msg.Params
		args = append(args, client.t("Help not found"))
		rb.Add(nil, server.name, ERR_HELPNOTFOUND, args...)
	}

	return false
}

// HISTORY <target> [<limit>]
// e.g., HISTORY #ubuntu 10
// HISTORY me 15
func historyHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	config := server.Config()
	if !config.History.Enabled {
		rb.Notice(client.t("This command has been disabled by the server administrators"))
		return false
	}

	target := msg.Params[0]
	var hist *history.Buffer
	channel := server.channels.Get(target)
	if channel != nil && channel.hasClient(client) {
		hist = &channel.history
	} else {
		if strings.ToLower(target) == "me" {
			hist = client.history
		} else {
			targetClient := server.clients.Get(target)
			if targetClient != nil {
				myAccount, targetAccount := client.Account(), targetClient.Account()
				if myAccount != "" && targetAccount != "" && myAccount == targetAccount {
					hist = targetClient.history
				}
			}
		}
	}

	if hist == nil {
		if channel == nil {
			rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.Nick(), target, client.t("No such channel"))
		} else {
			rb.Add(nil, server.name, ERR_NOTONCHANNEL, client.Nick(), target, client.t("You're not on that channel"))
		}
		return false
	}

	limit := 10
	maxChathistoryLimit := config.History.ChathistoryMax
	if len(msg.Params) > 1 {
		providedLimit, err := strconv.Atoi(msg.Params[1])
		if providedLimit > maxChathistoryLimit {
			providedLimit = maxChathistoryLimit
		}
		if err == nil && providedLimit != 0 {
			limit = providedLimit
		}
	}

	items := hist.Latest(limit)

	if channel != nil {
		channel.replayHistoryItems(rb, items, false)
	} else {
		client.replayPrivmsgHistory(rb, items, true)
	}

	return false
}

// INFO
func infoHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	// we do the below so that the human-readable lines in info can be translated.
	for _, line := range infoString1 {
		rb.Add(nil, server.name, RPL_INFO, client.nick, line)
	}
	rb.Add(nil, server.name, RPL_INFO, client.nick, client.t("Oragono is released under the MIT license."))
	rb.Add(nil, server.name, RPL_INFO, client.nick, "")
	rb.Add(nil, server.name, RPL_INFO, client.nick, client.t("Thanks to Jeremy Latt for founding Ergonomadic, the project this is based on")+" <3")
	rb.Add(nil, server.name, RPL_INFO, client.nick, "")
	rb.Add(nil, server.name, RPL_INFO, client.nick, client.t("Core Developers:"))
	for _, line := range infoString2 {
		rb.Add(nil, server.name, RPL_INFO, client.nick, line)
	}
	rb.Add(nil, server.name, RPL_INFO, client.nick, client.t("Contributors and Former Developers:"))
	for _, line := range infoString3 {
		rb.Add(nil, server.name, RPL_INFO, client.nick, line)
	}
	// show translators for languages other than good ole' regular English
	tlines := server.Languages().Translators()
	if 0 < len(tlines) {
		rb.Add(nil, server.name, RPL_INFO, client.nick, client.t("Translators:"))
		for _, line := range tlines {
			rb.Add(nil, server.name, RPL_INFO, client.nick, "    "+strings.Replace(line, "\n", ", ", -1))
		}
		rb.Add(nil, server.name, RPL_INFO, client.nick, "")
	}
	rb.Add(nil, server.name, RPL_ENDOFINFO, client.nick, client.t("End of /INFO"))
	return false
}

// INVITE <nickname> <channel>
func inviteHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	nickname := msg.Params[0]
	channelName := msg.Params[1]

	casefoldedNickname, err := CasefoldName(nickname)
	target := server.clients.Get(casefoldedNickname)
	if err != nil || target == nil {
		rb.Add(nil, server.name, ERR_NOSUCHNICK, client.nick, nickname, client.t("No such nick"))
		return false
	}

	casefoldedChannelName, err := CasefoldChannel(channelName)
	channel := server.channels.Get(casefoldedChannelName)
	if err != nil || channel == nil {
		rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, channelName, client.t("No such channel"))
		return false
	}

	channel.Invite(target, client, rb)
	return false
}

// ISON <nick>{ <nick>}
func isonHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	var nicks = msg.Params

	ison := make([]string, 0, len(msg.Params))
	for _, nick := range nicks {
		currentNick := server.getCurrentNick(nick)
		if currentNick != "" {
			ison = append(ison, currentNick)
		}
	}

	rb.Add(nil, server.name, RPL_ISON, client.nick, strings.Join(ison, " "))
	return false
}

// JOIN <channel>{,<channel>} [<key>{,<key>}]
func joinHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	// kill JOIN 0 requests
	if msg.Params[0] == "0" {
		rb.Notice(client.t("JOIN 0 is not allowed"))
		return false
	}

	// handle regular JOINs
	channels := strings.Split(msg.Params[0], ",")
	var keys []string
	if len(msg.Params) > 1 {
		keys = strings.Split(msg.Params[1], ",")
	}

	config := server.Config()
	oper := client.Oper()
	for i, name := range channels {
		if config.Channels.MaxChannelsPerClient <= client.NumChannels() && oper == nil {
			rb.Add(nil, server.name, ERR_TOOMANYCHANNELS, client.Nick(), name, client.t("You have joined too many channels"))
			return false
		}
		var key string
		if len(keys) > i {
			key = keys[i]
		}
		err := server.channels.Join(client, name, key, false, rb)
		if err == errNoSuchChannel {
			rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.Nick(), name, client.t("No such channel"))
		}
	}
	return false
}

// SAJOIN [nick] #channel{,#channel}
func sajoinHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	var target *Client
	var channelString string
	if strings.HasPrefix(msg.Params[0], "#") {
		target = client
		channelString = msg.Params[0]
	} else {
		if len(msg.Params) == 1 {
			rb.Add(nil, server.name, ERR_NEEDMOREPARAMS, client.Nick(), "KICK", client.t("Not enough parameters"))
			return false
		} else {
			target = server.clients.Get(msg.Params[0])
			if target == nil {
				rb.Add(nil, server.name, ERR_NOSUCHNICK, client.Nick(), msg.Params[0], "No such nick")
				return false
			}
			channelString = msg.Params[1]
		}
	}

	channels := strings.Split(channelString, ",")
	for _, chname := range channels {
		server.channels.Join(target, chname, "", true, rb)
	}
	return false
}

// KICK <channel>{,<channel>} <user>{,<user>} [<comment>]
func kickHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	channels := strings.Split(msg.Params[0], ",")
	users := strings.Split(msg.Params[1], ",")
	if (len(channels) != len(users)) && (len(users) != 1) {
		rb.Add(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, "KICK", client.t("Not enough parameters"))
		return false
	}

	var kicks [][]string
	for index, channel := range channels {
		if len(users) == 1 {
			kicks = append(kicks, []string{channel, users[0]})
		} else {
			kicks = append(kicks, []string{channel, users[index]})
		}
	}

	var comment string
	if len(msg.Params) > 2 {
		comment = msg.Params[2]
	}
	for _, info := range kicks {
		chname := info[0]
		nickname := info[1]
		casefoldedChname, err := CasefoldChannel(chname)
		channel := server.channels.Get(casefoldedChname)
		if err != nil || channel == nil {
			rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, chname, client.t("No such channel"))
			continue
		}

		casefoldedNickname, err := CasefoldName(nickname)
		target := server.clients.Get(casefoldedNickname)
		if err != nil || target == nil {
			rb.Add(nil, server.name, ERR_NOSUCHNICK, client.nick, nickname, client.t("No such nick"))
			continue
		}

		if comment == "" {
			comment = nickname
		}
		channel.Kick(client, target, comment, rb)
	}
	return false
}

// KILL <nickname> <comment>
func killHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	nickname := msg.Params[0]
	comment := "<no reason supplied>"
	if len(msg.Params) > 1 {
		comment = msg.Params[1]
	}

	casefoldedNickname, err := CasefoldName(nickname)
	target := server.clients.Get(casefoldedNickname)
	if err != nil || target == nil {
		rb.Add(nil, client.server.name, ERR_NOSUCHNICK, client.nick, nickname, client.t("No such nick"))
		return false
	}

	quitMsg := fmt.Sprintf("Killed (%s (%s))", client.nick, comment)

	server.snomasks.Send(sno.LocalKills, fmt.Sprintf(ircfmt.Unescape("%s$r was killed by %s $c[grey][$r%s$c[grey]]"), target.nick, client.nick, comment))
	target.exitedSnomaskSent = true

	target.Quit(quitMsg, nil)
	target.destroy(false, nil)
	return false
}

// KLINE [ANDKILL] [MYSELF] [duration] <mask> [ON <server>] [reason [| oper reason]]
// KLINE LIST
func klineHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	// check oper permissions
	oper := client.Oper()
	if oper == nil || !oper.Class.Capabilities["oper:local_ban"] {
		rb.Add(nil, server.name, ERR_NOPRIVS, client.nick, msg.Command, client.t("Insufficient oper privs"))
		return false
	}

	currentArg := 0

	// if they say LIST, we just list the current klines
	if len(msg.Params) == currentArg+1 && strings.ToLower(msg.Params[currentArg]) == "list" {
		bans := server.klines.AllBans()

		if len(bans) == 0 {
			client.Notice("No KLINEs have been set!")
		}

		for key, info := range bans {
			client.Notice(formatBanForListing(client, key, info))
		}

		return false
	}

	// when setting a ban, if they say "ANDKILL" we should also kill all users who match it
	var andKill bool
	if len(msg.Params) > currentArg+1 && strings.ToLower(msg.Params[currentArg]) == "andkill" {
		andKill = true
		currentArg++
	}

	// when setting a ban that covers the oper's current connection, we require them to say
	// "KLINE MYSELF" so that we're sure they really mean it.
	var klineMyself bool
	if len(msg.Params) > currentArg+1 && strings.ToLower(msg.Params[currentArg]) == "myself" {
		klineMyself = true
		currentArg++
	}

	// duration
	duration, err := custime.ParseDuration(msg.Params[currentArg])
	if err != nil {
		duration = 0
	} else {
		currentArg++
	}

	// get mask
	if len(msg.Params) < currentArg+1 {
		rb.Add(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, msg.Command, client.t("Not enough parameters"))
		return false
	}
	mask := strings.ToLower(msg.Params[currentArg])
	currentArg++

	// check mask
	if !strings.Contains(mask, "!") && !strings.Contains(mask, "@") {
		mask = mask + "!*@*"
	} else if !strings.Contains(mask, "@") {
		mask = mask + "@*"
	}

	matcher := ircmatch.MakeMatch(mask)

	for _, clientMask := range client.AllNickmasks() {
		if !klineMyself && matcher.Match(clientMask) {
			rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("This ban matches you. To KLINE yourself, you must use the command:  /KLINE MYSELF <arguments>"))
			return false
		}
	}

	// check remote
	if len(msg.Params) > currentArg && msg.Params[currentArg] == "ON" {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("Remote servers not yet supported"))
		return false
	}

	// get oper name
	operName := oper.Name
	if operName == "" {
		operName = server.name
	}

	// get comment(s)
	reason, operReason := getReasonsFromParams(msg.Params, currentArg)

	err = server.klines.AddMask(mask, duration, reason, operReason, operName)
	if err != nil {
		rb.Notice(fmt.Sprintf(client.t("Could not successfully save new K-LINE: %s"), err.Error()))
		return false
	}

	var snoDescription string
	if duration != 0 {
		rb.Notice(fmt.Sprintf(client.t("Added temporary (%[1]s) K-Line for %[2]s"), duration.String(), mask))
		snoDescription = fmt.Sprintf(ircfmt.Unescape("%s [%s]$r added temporary (%s) K-Line for %s"), client.nick, operName, duration.String(), mask)
	} else {
		rb.Notice(fmt.Sprintf(client.t("Added K-Line for %s"), mask))
		snoDescription = fmt.Sprintf(ircfmt.Unescape("%s [%s]$r added K-Line for %s"), client.nick, operName, mask)
	}
	server.snomasks.Send(sno.LocalXline, snoDescription)

	var killClient bool
	if andKill {
		var clientsToKill []*Client
		var killedClientNicks []string

		for _, mcl := range server.clients.AllClients() {
			for _, clientMask := range mcl.AllNickmasks() {
				if matcher.Match(clientMask) {
					clientsToKill = append(clientsToKill, mcl)
					killedClientNicks = append(killedClientNicks, mcl.nick)
				}
			}
		}

		for _, mcl := range clientsToKill {
			mcl.exitedSnomaskSent = true
			mcl.Quit(fmt.Sprintf(mcl.t("You have been banned from this server (%s)"), reason), nil)
			if mcl == client {
				killClient = true
			} else {
				// if mcl == client, we kill them below
				mcl.destroy(false, nil)
			}
		}

		// send snomask
		sort.Strings(killedClientNicks)
		server.snomasks.Send(sno.LocalKills, fmt.Sprintf(ircfmt.Unescape("%s [%s] killed %d clients with a KLINE $c[grey][$r%s$c[grey]]"), client.nick, operName, len(killedClientNicks), strings.Join(killedClientNicks, ", ")))
	}

	return killClient
}

// LANGUAGE <code>{ <code>}
func languageHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	nick := client.Nick()
	alreadyDoneLanguages := make(map[string]bool)
	var appliedLanguages []string

	lm := server.Languages()
	supportedLanguagesCount := lm.Count()
	if supportedLanguagesCount < len(msg.Params) {
		rb.Add(nil, client.server.name, ERR_TOOMANYLANGUAGES, nick, strconv.Itoa(supportedLanguagesCount), client.t("You specified too many languages"))
		return false
	}

	for _, value := range msg.Params {
		value = strings.ToLower(value)
		// strip ~ from the language if it has it
		value = strings.TrimPrefix(value, "~")

		// silently ignore empty languages or those with spaces in them
		if len(value) == 0 || strings.Contains(value, " ") {
			continue
		}

		_, exists := lm.Languages[value]
		if !exists {
			rb.Add(nil, client.server.name, ERR_NOLANGUAGE, nick, fmt.Sprintf(client.t("Language %s is not supported by this server"), value))
			return false
		}

		// if we've already applied the given language, skip it
		_, exists = alreadyDoneLanguages[value]
		if exists {
			continue
		}

		appliedLanguages = append(appliedLanguages, value)
	}

	var langsToSet []string
	if !(len(appliedLanguages) == 1 && appliedLanguages[0] == "en") {
		langsToSet = appliedLanguages
	}
	client.SetLanguages(langsToSet)

	params := make([]string, len(appliedLanguages)+2)
	params[0] = nick
	copy(params[1:], appliedLanguages)
	params[len(params)-1] = client.t("Language preferences have been set")

	rb.Add(nil, client.server.name, RPL_YOURLANGUAGESARE, params...)

	return false
}

// LIST [<channel>{,<channel>}] [<elistcond>{,<elistcond>}]
func listHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	// get channels
	var channels []string
	for _, param := range msg.Params {
		if 0 < len(param) && param[0] == '#' {
			for _, channame := range strings.Split(param, ",") {
				if 0 < len(channame) && channame[0] == '#' {
					channels = append(channels, channame)
				}
			}
		}
	}

	// get elist conditions
	var matcher elistMatcher
	for _, param := range msg.Params {
		if len(param) < 1 {
			continue
		}

		if param[0] == '<' {
			param = param[1:]
			val, err := strconv.Atoi(param)
			if err != nil {
				continue
			}
			matcher.MaxClientsActive = true
			matcher.MaxClients = val - 1 // -1 because < means less than the given number
		}
		if param[0] == '>' {
			param = param[1:]
			val, err := strconv.Atoi(param)
			if err != nil {
				continue
			}
			matcher.MinClientsActive = true
			matcher.MinClients = val + 1 // +1 because > means more than the given number
		}
	}

	clientIsOp := client.HasMode(modes.Operator)
	if len(channels) == 0 {
		for _, channel := range server.channels.Channels() {
			if !clientIsOp && channel.flags.HasMode(modes.Secret) {
				continue
			}
			if matcher.Matches(channel) {
				client.RplList(channel, rb)
			}
		}
	} else {
		// limit regular users to only listing one channel
		if !clientIsOp {
			channels = channels[:1]
		}

		for _, chname := range channels {
			casefoldedChname, err := CasefoldChannel(chname)
			channel := server.channels.Get(casefoldedChname)
			if err != nil || channel == nil || (!clientIsOp && channel.flags.HasMode(modes.Secret)) {
				if len(chname) > 0 {
					rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, chname, client.t("No such channel"))
				}
				continue
			}
			if matcher.Matches(channel) {
				client.RplList(channel, rb)
			}
		}
	}
	rb.Add(nil, server.name, RPL_LISTEND, client.nick, client.t("End of LIST"))
	return false
}

// LUSERS [<mask> [<server>]]
func lusersHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	//TODO(vegax87) Fix network statistics and additional parameters
	totalCount, invisibleCount, operCount := server.stats.GetStats()

	rb.Add(nil, server.name, RPL_LUSERCLIENT, client.nick, fmt.Sprintf(client.t("There are %[1]d users and %[2]d invisible on %[3]d server(s)"), totalCount-invisibleCount, invisibleCount, 1))
	rb.Add(nil, server.name, RPL_LUSEROP, client.nick, strconv.Itoa(operCount), client.t("IRC Operators online"))
	rb.Add(nil, server.name, RPL_LUSERCHANNELS, client.nick, strconv.Itoa(server.channels.Len()), client.t("channels formed"))
	rb.Add(nil, server.name, RPL_LUSERME, client.nick, fmt.Sprintf(client.t("I have %[1]d clients and %[2]d servers"), totalCount, 1))

	return false
}

// MODE <target> [<modestring> [<mode arguments>...]]
func modeHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	_, errChan := CasefoldChannel(msg.Params[0])

	if errChan == nil {
		return cmodeHandler(server, client, msg, rb)
	}
	return umodeHandler(server, client, msg, rb)
}

// MODE <channel> [<modestring> [<mode arguments>...]]
func cmodeHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	channelName, err := CasefoldChannel(msg.Params[0])
	channel := server.channels.Get(channelName)

	if err != nil || channel == nil {
		rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, msg.Params[0], client.t("No such channel"))
		return false
	}

	// applied mode changes
	applied := make(modes.ModeChanges, 0)

	if 1 < len(msg.Params) {
		// parse out real mode changes
		params := msg.Params[1:]
		changes, unknown := modes.ParseChannelModeChanges(params...)

		// alert for unknown mode changes
		for char := range unknown {
			rb.Add(nil, server.name, ERR_UNKNOWNMODE, client.nick, string(char), client.t("is an unknown mode character to me"))
		}
		if len(unknown) == 1 && len(changes) == 0 {
			return false
		}

		// apply mode changes
		applied = channel.ApplyChannelModeChanges(client, msg.Command == "SAMODE", changes, rb)
	}

	// save changes
	var includeFlags uint
	for _, change := range applied {
		includeFlags |= IncludeModes
		if change.Mode == modes.BanMask || change.Mode == modes.ExceptMask || change.Mode == modes.InviteMask {
			includeFlags |= IncludeLists
		}
	}

	if includeFlags != 0 {
		channel.MarkDirty(includeFlags)
	}

	// send out changes
	prefix := client.NickMaskString()
	if len(applied) > 0 {
		//TODO(dan): we should change the name of String and make it return a slice here
		args := append([]string{channel.name}, strings.Split(applied.String(), " ")...)
		for _, member := range channel.Members() {
			if member == client {
				rb.Add(nil, prefix, "MODE", args...)
				for _, session := range client.Sessions() {
					if session != rb.session {
						session.Send(nil, prefix, "MODE", args...)
					}
				}
			} else {
				member.Send(nil, prefix, "MODE", args...)
			}
		}
	} else {
		args := append([]string{client.nick, channel.name}, channel.modeStrings(client)...)
		rb.Add(nil, prefix, RPL_CHANNELMODEIS, args...)
		rb.Add(nil, client.nickMaskString, RPL_CHANNELCREATED, client.nick, channel.name, strconv.FormatInt(channel.createdTime.Unix(), 10))
	}
	return false
}

// MODE <client> [<modestring> [<mode arguments>...]]
func umodeHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	nickname, err := CasefoldName(msg.Params[0])
	target := server.clients.Get(nickname)
	if err != nil || target == nil {
		if len(msg.Params[0]) > 0 {
			rb.Add(nil, server.name, ERR_NOSUCHNICK, client.nick, msg.Params[0], client.t("No such nick"))
		}
		return false
	}

	targetNick := target.Nick()
	hasPrivs := client == target || msg.Command == "SAMODE"

	if !hasPrivs {
		if len(msg.Params) > 1 {
			rb.Add(nil, server.name, ERR_USERSDONTMATCH, client.nick, client.t("Can't change modes for other users"))
		} else {
			rb.Add(nil, server.name, ERR_USERSDONTMATCH, client.nick, client.t("Can't view modes for other users"))
		}
		return false
	}

	// applied mode changes
	applied := make(modes.ModeChanges, 0)

	if 1 < len(msg.Params) {
		// parse out real mode changes
		params := msg.Params[1:]
		changes, unknown := modes.ParseUserModeChanges(params...)

		// alert for unknown mode changes
		for char := range unknown {
			rb.Add(nil, server.name, ERR_UNKNOWNMODE, client.nick, string(char), client.t("is an unknown mode character to me"))
		}
		if len(unknown) == 1 && len(changes) == 0 {
			return false
		}

		// apply mode changes
		applied = ApplyUserModeChanges(client, changes, msg.Command == "SAMODE")
	}

	if len(applied) > 0 {
		rb.Add(nil, client.nickMaskString, "MODE", targetNick, applied.String())
	} else if hasPrivs {
		rb.Add(nil, target.nickMaskString, RPL_UMODEIS, targetNick, target.ModeString())
		if client.HasMode(modes.LocalOperator) || client.HasMode(modes.Operator) {
			masks := server.snomasks.String(client)
			if 0 < len(masks) {
				rb.Add(nil, target.nickMaskString, RPL_SNOMASKIS, targetNick, masks, client.t("Server notice masks"))
			}
		}
	}
	return false
}

// get the correct capitalization of a nick (if it's online), otherwise return ""
func (server *Server) getCurrentNick(nick string) (result string) {
	if service, isService := OragonoServices[strings.ToLower(nick)]; isService {
		return service.Name
	} else if iclient := server.clients.Get(nick); iclient != nil {
		return iclient.Nick()
	}
	return ""
}

// MONITOR <subcmd> [params...]
func monitorHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	handler, exists := monitorSubcommands[strings.ToLower(msg.Params[0])]

	if !exists {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.Nick(), "MONITOR", msg.Params[0], client.t("Unknown subcommand"))
		return false
	}

	return handler(server, client, msg, rb)
}

// MONITOR - <target>{,<target>}
func monitorRemoveHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	if len(msg.Params) < 2 {
		rb.Add(nil, server.name, ERR_NEEDMOREPARAMS, client.Nick(), msg.Command, client.t("Not enough parameters"))
		return false
	}

	targets := strings.Split(msg.Params[1], ",")
	for _, target := range targets {
		cfnick, err := CasefoldName(target)
		if err != nil {
			continue
		}
		server.monitorManager.Remove(client, cfnick)
	}

	return false
}

// MONITOR + <target>{,<target>}
func monitorAddHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	if len(msg.Params) < 2 {
		rb.Add(nil, server.name, ERR_NEEDMOREPARAMS, client.Nick(), msg.Command, client.t("Not enough parameters"))
		return false
	}

	var online []string
	var offline []string

	limits := server.Limits()

	targets := strings.Split(msg.Params[1], ",")
	for _, target := range targets {
		// check name length
		if len(target) < 1 || len(targets) > limits.NickLen {
			continue
		}

		// add target
		casefoldedTarget, err := CasefoldName(target)
		if err != nil {
			continue
		}

		err = server.monitorManager.Add(client, casefoldedTarget, limits.MonitorEntries)
		if err == errMonitorLimitExceeded {
			rb.Add(nil, server.name, ERR_MONLISTFULL, client.Nick(), strconv.Itoa(limits.MonitorEntries), strings.Join(targets, ","))
			break
		} else if err != nil {
			continue
		}

		currentNick := server.getCurrentNick(target)
		// add to online / offline lists
		if currentNick != "" {
			online = append(online, currentNick)
		} else {
			offline = append(offline, target)
		}
	}

	if len(online) > 0 {
		rb.Add(nil, server.name, RPL_MONONLINE, client.Nick(), strings.Join(online, ","))
	}
	if len(offline) > 0 {
		rb.Add(nil, server.name, RPL_MONOFFLINE, client.Nick(), strings.Join(offline, ","))
	}

	return false
}

// MONITOR C
func monitorClearHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	server.monitorManager.RemoveAll(client)
	return false
}

// MONITOR L
func monitorListHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	nick := client.Nick()
	monitorList := server.monitorManager.List(client)

	var nickList []string
	for _, cfnick := range monitorList {
		replynick := cfnick
		currentNick := server.getCurrentNick(cfnick)
		// report the uncasefolded nick if it's available, i.e., the client is online
		if currentNick != "" {
			replynick = currentNick
		}
		nickList = append(nickList, replynick)
	}

	for _, line := range utils.ArgsToStrings(maxLastArgLength, nickList, ",") {
		rb.Add(nil, server.name, RPL_MONLIST, nick, line)
	}

	rb.Add(nil, server.name, RPL_ENDOFMONLIST, nick, "End of MONITOR list")

	return false
}

// MONITOR S
func monitorStatusHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	var online []string
	var offline []string

	monitorList := server.monitorManager.List(client)

	for _, name := range monitorList {
		currentNick := server.getCurrentNick(name)
		if currentNick != "" {
			online = append(online, currentNick)
		} else {
			offline = append(offline, name)
		}
	}

	if len(online) > 0 {
		for _, line := range utils.ArgsToStrings(maxLastArgLength, online, ",") {
			rb.Add(nil, server.name, RPL_MONONLINE, client.Nick(), line)
		}
	}
	if len(offline) > 0 {
		for _, line := range utils.ArgsToStrings(maxLastArgLength, offline, ",") {
			rb.Add(nil, server.name, RPL_MONOFFLINE, client.Nick(), line)
		}
	}

	return false
}

// MOTD
func motdHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	server.MOTD(client, rb)
	return false
}

// NAMES [<channel>{,<channel>} [target]]
func namesHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	var channels []string
	if len(msg.Params) > 0 {
		channels = strings.Split(msg.Params[0], ",")
	}

	// TODO: in a post-federation world, process `target` (server to forward request to)

	if len(channels) == 0 {
		for _, channel := range server.channels.Channels() {
			channel.Names(client, rb)
		}
		return false
	}

	for _, chname := range channels {
		channel := server.channels.Get(chname)
		if channel != nil {
			channel.Names(client, rb)
		} else if chname != "" {
			rb.Add(nil, server.name, RPL_ENDOFNAMES, client.Nick(), chname, client.t("End of NAMES list"))
		}
	}
	return false
}

// NICK <nickname>
func nickHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	if client.registered {
		performNickChange(server, client, client, nil, msg.Params[0], rb)
	} else {
		client.preregNick = msg.Params[0]
	}
	return false
}

// NOTICE <target>{,<target>} <message>
// PRIVMSG <target>{,<target>} <message>
// TAGMSG <target>{,<target>}
func messageHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	histType, err := msgCommandToHistType(server, msg.Command)
	if err != nil {
		return false
	}

	cnick := client.Nick()
	clientOnlyTags := msg.ClientOnlyTags()
	if histType == history.Tagmsg && len(clientOnlyTags) == 0 {
		// nothing to do
		return false
	}

	targets := strings.Split(msg.Params[0], ",")
	var message string
	if len(msg.Params) > 1 {
		message = msg.Params[1]
	}

	// note that error replies are never sent for NOTICE

	if client.isTor && isRestrictedCTCPMessage(message) {
		if histType != history.Notice {
			rb.Add(nil, server.name, "NOTICE", client.t("CTCP messages are disabled over Tor"))
		}
		return false
	}

	for i, targetString := range targets {
		// each target gets distinct msgids
		splitMsg := utils.MakeSplitMessage(message, !rb.session.capabilities.Has(caps.MaxLine))

		// max of four targets per privmsg
		if i > maxTargets-1 {
			break
		}
		prefixes, targetString := modes.SplitChannelMembershipPrefixes(targetString)
		lowestPrefix := modes.GetLowestChannelModePrefix(prefixes)

		if len(targetString) == 0 {
			continue
		} else if targetString[0] == '#' {
			channel := server.channels.Get(targetString)
			if channel == nil {
				if histType != history.Notice {
					rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, cnick, targetString, client.t("No such channel"))
				}
				continue
			}
			channel.SendSplitMessage(msg.Command, lowestPrefix, clientOnlyTags, client, splitMsg, rb)
		} else {
			// NOTICE and TAGMSG to services are ignored
			if histType == history.Privmsg {
				lowercaseTarget := strings.ToLower(targetString)
				if service, isService := OragonoServices[lowercaseTarget]; isService {
					servicePrivmsgHandler(service, server, client, message, rb)
					continue
				} else if _, isZNC := zncHandlers[lowercaseTarget]; isZNC {
					zncPrivmsgHandler(client, lowercaseTarget, message, rb)
					continue
				}
			}

			user := server.clients.Get(targetString)
			if user == nil {
				if histType != history.Notice {
					rb.Add(nil, server.name, ERR_NOSUCHNICK, cnick, targetString, "No such nick")
				}
				continue
			}
			tnick := user.Nick()

			nickMaskString := client.NickMaskString()
			accountName := client.AccountName()
			// restrict messages appropriately when +R is set
			// intentionally make the sending user think the message went through fine
			allowedPlusR := !user.HasMode(modes.RegisteredOnly) || client.LoggedIntoAccount()
			allowedTor := !user.isTor || !isRestrictedCTCPMessage(message)
			if allowedPlusR && allowedTor {
				for _, session := range user.Sessions() {
					if histType == history.Tagmsg {
						// don't send TAGMSG at all if they don't have the tags cap
						if session.capabilities.Has(caps.MessageTags) {
							session.sendFromClientInternal(false, splitMsg.Time, splitMsg.Msgid, nickMaskString, accountName, clientOnlyTags, msg.Command, tnick)
						}
					} else {
						session.sendSplitMsgFromClientInternal(false, nickMaskString, accountName, clientOnlyTags, msg.Command, tnick, splitMsg)
					}
				}
			}
			// an echo-message may need to be included in the response:
			if rb.session.capabilities.Has(caps.EchoMessage) {
				if histType == history.Tagmsg && rb.session.capabilities.Has(caps.MessageTags) {
					rb.AddFromClient(splitMsg.Time, splitMsg.Msgid, nickMaskString, accountName, clientOnlyTags, msg.Command, tnick)
				} else {
					rb.AddSplitMessageFromClient(nickMaskString, accountName, clientOnlyTags, msg.Command, tnick, splitMsg)
				}
			}
			// an echo-message may need to go out to other client sessions:
			for _, session := range client.Sessions() {
				if session == rb.session {
					continue
				}
				if histType == history.Tagmsg && rb.session.capabilities.Has(caps.MessageTags) {
					session.sendFromClientInternal(false, splitMsg.Time, splitMsg.Msgid, nickMaskString, accountName, clientOnlyTags, msg.Command, tnick)
				} else if histType != history.Tagmsg {
					session.sendSplitMsgFromClientInternal(false, nickMaskString, accountName, clientOnlyTags, msg.Command, tnick, splitMsg)
				}
			}
			if histType != history.Notice && user.Away() {
				//TODO(dan): possibly implement cooldown of away notifications to users
				rb.Add(nil, server.name, RPL_AWAY, cnick, tnick, user.AwayMessage())
			}

			item := history.Item{
				Type:        histType,
				Message:     splitMsg,
				Nick:        nickMaskString,
				AccountName: accountName,
			}
			// add to the target's history:
			user.history.Add(item)
			// add this to the client's history as well, recording the target:
			item.Params[0] = tnick
			client.history.Add(item)
		}
	}
	return false
}

// NPC <target> <sourcenick> <message>
func npcHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	target := msg.Params[0]
	fakeSource := msg.Params[1]
	message := msg.Params[2]

	_, err := CasefoldName(fakeSource)
	if err != nil {
		client.Send(nil, client.server.name, ERR_CANNOTSENDRP, target, client.t("Fake source must be a valid nickname"))
		return false
	}

	sourceString := fmt.Sprintf(npcNickMask, fakeSource, client.nick)

	sendRoleplayMessage(server, client, sourceString, target, false, message, rb)

	return false
}

// NPCA <target> <sourcenick> <message>
func npcaHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	target := msg.Params[0]
	fakeSource := msg.Params[1]
	message := msg.Params[2]
	sourceString := fmt.Sprintf(npcNickMask, fakeSource, client.nick)

	_, err := CasefoldName(fakeSource)
	if err != nil {
		client.Send(nil, client.server.name, ERR_CANNOTSENDRP, target, client.t("Fake source must be a valid nickname"))
		return false
	}

	sendRoleplayMessage(server, client, sourceString, target, true, message, rb)

	return false
}

// OPER <name> <password>
func operHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	if client.HasMode(modes.Operator) {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.Nick(), "OPER", client.t("You're already opered-up!"))
		return false
	}

	authorized := false
	oper := server.GetOperator(msg.Params[0])
	if oper != nil {
		password := []byte(msg.Params[1])
		authorized = (bcrypt.CompareHashAndPassword(oper.Pass, password) == nil)
	}
	if !authorized {
		rb.Add(nil, server.name, ERR_PASSWDMISMATCH, client.Nick(), client.t("Password incorrect"))
		client.Quit(client.t("Password incorrect"), rb.session)
		return true
	}

	oldNickmask := client.NickMaskString()
	client.SetOper(oper)
	if client.NickMaskString() != oldNickmask {
		client.sendChghost(oldNickmask, oper.Vhost)
	}

	// set new modes: modes.Operator, plus anything specified in the config
	modeChanges := make([]modes.ModeChange, len(oper.Modes)+1)
	modeChanges[0] = modes.ModeChange{
		Mode: modes.Operator,
		Op:   modes.Add,
	}
	copy(modeChanges[1:], oper.Modes)
	applied := ApplyUserModeChanges(client, modeChanges, true)

	rb.Add(nil, server.name, RPL_YOUREOPER, client.nick, client.t("You are now an IRC operator"))
	rb.Add(nil, server.name, "MODE", client.nick, applied.String())

	server.snomasks.Send(sno.LocalOpers, fmt.Sprintf(ircfmt.Unescape("Client opered up $c[grey][$r%s$c[grey], $r%s$c[grey]]"), client.nickMaskString, oper.Name))

	// client may now be unthrottled by the fakelag system
	for _, session := range client.Sessions() {
		session.resetFakelag()
	}

	return false
}

// PART <channel>{,<channel>} [<reason>]
func partHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	channels := strings.Split(msg.Params[0], ",")
	var reason string //TODO(dan): if this isn't supplied here, make sure the param doesn't exist in the PART message sent to other users
	if len(msg.Params) > 1 {
		reason = msg.Params[1]
	}

	for _, chname := range channels {
		err := server.channels.Part(client, chname, reason, rb)
		if err == errNoSuchChannel {
			rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, chname, client.t("No such channel"))
		}
	}
	return false
}

// PASS <password>
func passHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	if client.registered {
		rb.Add(nil, server.name, ERR_ALREADYREGISTRED, client.nick, client.t("You may not reregister"))
		return false
	}

	// if no password exists, skip checking
	serverPassword := server.Password()
	if serverPassword == nil {
		return false
	}

	// check the provided password
	password := []byte(msg.Params[0])
	if bcrypt.CompareHashAndPassword(serverPassword, password) != nil {
		rb.Add(nil, server.name, ERR_PASSWDMISMATCH, client.nick, client.t("Password incorrect"))
		client.Quit(client.t("Password incorrect"), rb.session)
		return true
	}

	client.sentPassCommand = true
	return false
}

// PING [params...]
func pingHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	rb.Add(nil, server.name, "PONG", msg.Params...)
	return false
}

// PONG [params...]
func pongHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	// client gets touched when they send this command, so we don't need to do anything
	return false
}

func isRestrictedCTCPMessage(message string) bool {
	// block all CTCP privmsgs to Tor clients except for ACTION
	// DCC can potentially be used for deanonymization, the others for fingerprinting
	return strings.HasPrefix(message, "\x01") && !strings.HasPrefix(message, "\x01ACTION")
}

// QUIT [<reason>]
func quitHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	reason := "Quit"
	if len(msg.Params) > 0 {
		reason += ": " + msg.Params[0]
	}
	client.Quit(reason, rb.session)
	return true
}

// REHASH
func rehashHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	server.logger.Info("server", fmt.Sprintf("REHASH command used by %s", client.nick))
	err := server.rehash()

	if err == nil {
		rb.Add(nil, server.name, RPL_REHASHING, client.nick, "ircd.yaml", client.t("Rehashing"))
	} else {
		server.logger.Error("server", fmt.Sprintln("Failed to rehash:", err.Error()))
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.nick, "REHASH", err.Error())
	}
	return false
}

// RENAME <oldchan> <newchan> [<reason>]
func renameHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) (result bool) {
	result = false
	oldName, newName := msg.Params[0], msg.Params[1]
	if newName == "" {
		newName = "<empty>" // intentionally invalid channel name, will error as expected
	}
	var reason string
	if 2 < len(msg.Params) {
		reason = msg.Params[2]
	}

	channel := server.channels.Get(oldName)
	if channel == nil {
		rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.Nick(), oldName, client.t("No such channel"))
		return false
	}
	if !(channel.ClientIsAtLeast(client, modes.Operator) || client.HasRoleCapabs("chanreg")) {
		rb.Add(nil, server.name, ERR_CHANOPRIVSNEEDED, client.Nick(), oldName, client.t("You're not a channel operator"))
		return false
	}

	founder := channel.Founder()
	if founder != "" && founder != client.Account() {
		rb.Add(nil, server.name, ERR_CANNOTRENAME, client.Nick(), oldName, newName, client.t("Only channel founders can change registered channels"))
		return false
	}

	// perform the channel rename
	err := server.channels.Rename(oldName, newName)
	if err == errInvalidChannelName {
		rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.Nick(), newName, client.t(err.Error()))
	} else if err == errChannelNameInUse {
		rb.Add(nil, server.name, ERR_CHANNAMEINUSE, client.Nick(), newName, client.t(err.Error()))
	} else if err != nil {
		rb.Add(nil, server.name, ERR_CANNOTRENAME, client.Nick(), oldName, newName, client.t("Cannot rename channel"))
	}
	if err != nil {
		return false
	}

	// send RENAME messages
	clientPrefix := client.NickMaskString()
	for _, mcl := range channel.Members() {
		for _, mSession := range mcl.Sessions() {
			targetRb := rb
			targetPrefix := clientPrefix
			if mSession != rb.session {
				targetRb = NewResponseBuffer(mSession)
				targetPrefix = mcl.NickMaskString()
			}
			if mSession.capabilities.Has(caps.Rename) {
				if reason != "" {
					targetRb.Add(nil, clientPrefix, "RENAME", oldName, newName, reason)
				} else {
					targetRb.Add(nil, clientPrefix, "RENAME", oldName, newName)
				}
			} else {
				if reason != "" {
					targetRb.Add(nil, targetPrefix, "PART", oldName, fmt.Sprintf(mcl.t("Channel renamed: %s"), reason))
				} else {
					targetRb.Add(nil, targetPrefix, "PART", oldName, fmt.Sprintf(mcl.t("Channel renamed")))
				}
				if mSession.capabilities.Has(caps.ExtendedJoin) {
					targetRb.Add(nil, targetPrefix, "JOIN", newName, mcl.AccountName(), mcl.Realname())
				} else {
					targetRb.Add(nil, targetPrefix, "JOIN", newName)
				}
				channel.SendTopic(mcl, targetRb, false)
				channel.Names(mcl, targetRb)
			}
			if mcl != client {
				targetRb.Send(false)
			}
		}
	}

	return false
}

// RESUME <token> [timestamp]
func resumeHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	token := msg.Params[0]

	if client.registered {
		rb.Add(nil, server.name, "RESUME", "ERR", client.t("Cannot resume connection, connection registration has already been completed"))
		return false
	}

	var timestamp time.Time
	if 1 < len(msg.Params) {
		ts, err := time.Parse(IRCv3TimestampFormat, msg.Params[1])
		if err == nil {
			timestamp = ts
		} else {
			rb.Add(nil, server.name, "RESUME", "WARN", client.t("Timestamp is not in 2006-01-02T15:04:05.999Z format, ignoring it"))
		}
	}

	client.resumeDetails = &ResumeDetails{
		Timestamp:      timestamp,
		PresentedToken: token,
	}

	return false
}

// SANICK <oldnick> <nickname>
func sanickHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	targetNick := strings.TrimSpace(msg.Params[0])
	target := server.clients.Get(targetNick)
	if target == nil {
		rb.Add(nil, server.name, ERR_NOSUCHNICK, client.nick, msg.Params[0], client.t("No such nick"))
		return false
	}
	performNickChange(server, client, target, nil, msg.Params[1], rb)
	return false
}

// SCENE <target> <message>
func sceneHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	target := msg.Params[0]
	message := msg.Params[1]
	sourceString := fmt.Sprintf(sceneNickMask, client.nick)

	sendRoleplayMessage(server, client, sourceString, target, false, message, rb)

	return false
}

// SETNAME <realname>
func setnameHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	realname := msg.Params[0]

	client.stateMutex.Lock()
	client.realname = realname
	client.stateMutex.Unlock()

	details := client.Details()

	// alert friends
	now := time.Now().UTC()
	for session := range client.Friends(caps.SetName) {
		session.sendFromClientInternal(false, now, "", details.nickMask, details.account, nil, "SETNAME", details.realname)
	}

	return false
}

// TIME
func timeHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	rb.Add(nil, server.name, RPL_TIME, client.nick, server.name, time.Now().UTC().Format(time.RFC1123))
	return false
}

// TOPIC <channel> [<topic>]
func topicHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	name, err := CasefoldChannel(msg.Params[0])
	channel := server.channels.Get(name)
	if err != nil || channel == nil {
		if len(msg.Params[0]) > 0 {
			rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, msg.Params[0], client.t("No such channel"))
		}
		return false
	}

	if len(msg.Params) > 1 {
		channel.SetTopic(client, msg.Params[1], rb)
	} else {
		channel.SendTopic(client, rb, true)
	}
	return false
}

// UNDLINE <ip>|<net>
func unDLineHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	// check oper permissions
	oper := client.Oper()
	if oper == nil || !oper.Class.Capabilities["oper:local_unban"] {
		rb.Add(nil, server.name, ERR_NOPRIVS, client.nick, msg.Command, client.t("Insufficient oper privs"))
		return false
	}

	// get host
	hostString := msg.Params[0]

	// check host
	hostNet, err := utils.NormalizedNetFromString(hostString)

	if err != nil {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("Could not parse IP address or CIDR network"))
		return false
	}

	err = server.dlines.RemoveNetwork(hostNet)

	if err != nil {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, fmt.Sprintf(client.t("Could not remove ban [%s]"), err.Error()))
		return false
	}

	hostString = utils.NetToNormalizedString(hostNet)
	rb.Notice(fmt.Sprintf(client.t("Removed D-Line for %s"), hostString))
	server.snomasks.Send(sno.LocalXline, fmt.Sprintf(ircfmt.Unescape("%s$r removed D-Line for %s"), client.nick, hostString))
	return false
}

// UNKLINE <mask>
func unKLineHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	// check oper permissions
	oper := client.Oper()
	if oper == nil || !oper.Class.Capabilities["oper:local_unban"] {
		rb.Add(nil, server.name, ERR_NOPRIVS, client.nick, msg.Command, client.t("Insufficient oper privs"))
		return false
	}

	// get host
	mask := msg.Params[0]

	if !strings.Contains(mask, "!") && !strings.Contains(mask, "@") {
		mask = mask + "!*@*"
	} else if !strings.Contains(mask, "@") {
		mask = mask + "@*"
	}

	err := server.klines.RemoveMask(mask)

	if err != nil {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, fmt.Sprintf(client.t("Could not remove ban [%s]"), err.Error()))
		return false
	}

	rb.Notice(fmt.Sprintf(client.t("Removed K-Line for %s"), mask))
	server.snomasks.Send(sno.LocalXline, fmt.Sprintf(ircfmt.Unescape("%s$r removed K-Line for %s"), client.nick, mask))
	return false
}

// USER <username> * 0 <realname>
func userHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	if client.registered {
		rb.Add(nil, server.name, ERR_ALREADYREGISTRED, client.Nick(), client.t("You may not reregister"))
		return false
	}

	err := client.SetNames(msg.Params[0], msg.Params[3], false)
	if err == errInvalidUsername {
		// if client's using a unicode nick or something weird, let's just set 'em up with a stock username instead.
		// fixes clients that just use their nick as a username so they can still use the interesting nick
		if client.preregNick == msg.Params[0] {
			client.SetNames("user", msg.Params[3], false)
		} else {
			rb.Add(nil, server.name, ERR_INVALIDUSERNAME, client.Nick(), client.t("Malformed username"))
		}
	}

	return false
}

// USERHOST <nickname>{ <nickname>}
func userhostHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	returnedNicks := make(map[string]bool)

	for i, nickname := range msg.Params {
		if i >= 10 {
			break
		}

		casefoldedNickname, err := CasefoldName(nickname)
		target := server.clients.Get(casefoldedNickname)
		if err != nil || target == nil {
			rb.Add(nil, client.server.name, ERR_NOSUCHNICK, client.nick, nickname, client.t("No such nick"))
			return false
		}
		if returnedNicks[casefoldedNickname] {
			continue
		}

		// to prevent returning multiple results for a single nick
		returnedNicks[casefoldedNickname] = true

		var isOper, isAway string

		if target.HasMode(modes.Operator) {
			isOper = "*"
		}
		if target.Away() {
			isAway = "-"
		} else {
			isAway = "+"
		}
		rb.Add(nil, client.server.name, RPL_USERHOST, client.nick, fmt.Sprintf("%s%s=%s%s@%s", target.nick, isOper, isAway, target.username, target.hostname))
	}

	return false
}

// VERSION
func versionHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	rb.Add(nil, server.name, RPL_VERSION, client.nick, Ver, server.name)
	client.RplISupport(rb)
	return false
}

// WEBIRC <password> <gateway> <hostname> <ip> [:flag1 flag2=x flag3]
func webircHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	// only allow unregistered clients to use this command
	if client.registered || client.proxiedIP != nil {
		return false
	}

	// process flags
	var secure bool
	if 4 < len(msg.Params) {
		for _, x := range strings.Split(msg.Params[4], " ") {
			// split into key=value
			var key string
			if strings.Contains(x, "=") {
				y := strings.SplitN(x, "=", 2)
				key, _ = y[0], y[1]
			} else {
				key = x
			}

			lkey := strings.ToLower(key)
			if lkey == "tls" || lkey == "secure" {
				// only accept "tls" flag if the gateway's connection to us is secure as well
				if client.HasMode(modes.TLS) || client.realIP.IsLoopback() {
					secure = true
				}
			}
		}
	}

	givenPassword := []byte(msg.Params[0])
	for _, info := range server.Config().Server.WebIRC {
		if utils.IPInNets(client.realIP, info.allowedNets) {
			// confirm password and/or fingerprint
			if 0 < len(info.Password) && bcrypt.CompareHashAndPassword(info.Password, givenPassword) != nil {
				continue
			}
			if 0 < len(info.Fingerprint) && client.certfp != info.Fingerprint {
				continue
			}

			proxiedIP := msg.Params[3]
			// see #211; websocket gateways will wrap ipv6 addresses in square brackets
			// because IRC parameters can't start with :
			if strings.HasPrefix(proxiedIP, "[") && strings.HasSuffix(proxiedIP, "]") {
				proxiedIP = proxiedIP[1 : len(proxiedIP)-1]
			}
			err, quitMsg := client.ApplyProxiedIP(rb.session, proxiedIP, secure)
			if err != nil {
				client.Quit(quitMsg, rb.session)
				return true
			} else {
				return false
			}
		}
	}

	client.Quit(client.t("WEBIRC command is not usable from your address or incorrect password given"), rb.session)
	return true
}

// WHO [<mask> [o]]
func whoHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	if msg.Params[0] == "" {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.nick, "WHO", client.t("First param must be a mask or channel"))
		return false
	}

	var mask string
	if len(msg.Params) > 0 {
		casefoldedMask, err := Casefold(msg.Params[0])
		if err != nil {
			rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.Nick(), "WHO", client.t("Mask isn't valid"))
			return false
		}
		mask = casefoldedMask
	}

	//TODO(dan): is this used and would I put this param in the Modern doc?
	// if not, can we remove it?
	//var operatorOnly bool
	//if len(msg.Params) > 1 && msg.Params[1] == "o" {
	//	operatorOnly = true
	//}

	isOper := client.HasMode(modes.Operator)
	if mask[0] == '#' {
		// TODO implement wildcard matching
		//TODO(dan): ^ only for opers
		channel := server.channels.Get(mask)
		if channel != nil {
			isJoined := channel.hasClient(client)
			if !channel.flags.HasMode(modes.Secret) || isJoined || isOper {
				for _, member := range channel.Members() {
					if !member.HasMode(modes.Invisible) || isJoined || isOper {
						client.rplWhoReply(channel, member, rb)
					}
				}
			}
		}
	} else {
		for mclient := range server.clients.FindAll(mask) {
			client.rplWhoReply(nil, mclient, rb)
		}
	}

	rb.Add(nil, server.name, RPL_ENDOFWHO, client.nick, mask, client.t("End of WHO list"))
	return false
}

// WHOIS [<target>] <mask>{,<mask>}
func whoisHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	var masksString string
	//var target string

	if len(msg.Params) > 1 {
		//target = msg.Params[0]
		masksString = msg.Params[1]
	} else {
		masksString = msg.Params[0]
	}

	if len(strings.TrimSpace(masksString)) < 1 {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("No masks given"))
		return false
	}

	handleService := func(nick string) bool {
		cfnick, _ := CasefoldName(nick)
		service, ok := OragonoServices[cfnick]
		if !ok {
			return false
		}
		clientNick := client.Nick()
		rb.Add(nil, client.server.name, RPL_WHOISUSER, clientNick, service.Name, service.Name, "localhost", "*", fmt.Sprintf(client.t("Network service, for more info /msg %s HELP"), service.Name))
		// hehe
		if client.HasMode(modes.TLS) {
			rb.Add(nil, client.server.name, RPL_WHOISSECURE, clientNick, service.Name, client.t("is using a secure connection"))
		}
		return true
	}

	if client.HasMode(modes.Operator) {
		for _, mask := range strings.Split(masksString, ",") {
			matches := server.clients.FindAll(mask)
			if len(matches) == 0 && !handleService(mask) {
				rb.Add(nil, client.server.name, ERR_NOSUCHNICK, client.nick, mask, client.t("No such nick"))
				continue
			}
			for mclient := range matches {
				client.getWhoisOf(mclient, rb)
			}
		}
	} else {
		// only get the first request; also require a nick, not a mask
		nick := strings.Split(masksString, ",")[0]
		mclient := server.clients.Get(nick)
		if mclient != nil {
			client.getWhoisOf(mclient, rb)
		} else if !handleService(nick) {
			rb.Add(nil, client.server.name, ERR_NOSUCHNICK, client.nick, masksString, client.t("No such nick"))
		}
		// fall through, ENDOFWHOIS is always sent
	}
	rb.Add(nil, server.name, RPL_ENDOFWHOIS, client.nick, masksString, client.t("End of /WHOIS list"))
	return false
}

// WHOWAS <nickname> [<count> [<server>]]
func whowasHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	nicknames := strings.Split(msg.Params[0], ",")

	// 0 means "all the entries", as does a negative number
	var count uint64
	if len(msg.Params) > 1 {
		count, _ = strconv.ParseUint(msg.Params[1], 10, 64)
	}
	//var target string
	//if len(msg.Params) > 2 {
	//	target = msg.Params[2]
	//}
	cnick := client.Nick()
	for _, nickname := range nicknames {
		results := server.whoWas.Find(nickname, int(count))
		if len(results) == 0 {
			if len(nickname) > 0 {
				rb.Add(nil, server.name, ERR_WASNOSUCHNICK, cnick, nickname, client.t("There was no such nickname"))
			}
		} else {
			for _, whoWas := range results {
				rb.Add(nil, server.name, RPL_WHOWASUSER, cnick, whoWas.nick, whoWas.username, whoWas.hostname, "*", whoWas.realname)
			}
		}
		if len(nickname) > 0 {
			rb.Add(nil, server.name, RPL_ENDOFWHOWAS, cnick, nickname, client.t("End of WHOWAS"))
		}
	}
	return false
}

// ZNC <module> [params]
func zncHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	zncModuleHandler(client, msg.Params[0], msg.Params[1:], rb)
	return false
}
