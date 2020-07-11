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
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/oragono/oragono/irc/caps"
	"github.com/oragono/oragono/irc/custime"
	"github.com/oragono/oragono/irc/history"
	"github.com/oragono/oragono/irc/jwt"
	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/sno"
	"github.com/oragono/oragono/irc/utils"
	"golang.org/x/crypto/bcrypt"
)

// helper function to parse ACC callbacks, e.g., mailto:person@example.com, tel:16505551234
func parseCallback(spec string, config AccountConfig) (callbackNamespace string, callbackValue string) {
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

func registrationErrorToMessageAndCode(err error) (message, code string) {
	// default responses: let's be risk-averse about displaying internal errors
	// to the clients, especially for something as sensitive as accounts
	code = "REG_UNSPECIFIED_ERROR"
	message = `Could not register`
	switch err {
	case errAccountBadPassphrase:
		code = "REG_INVALID_CREDENTIAL"
		message = err.Error()
	case errAccountAlreadyRegistered, errAccountAlreadyVerified, errAccountAlreadyUnregistered, errAccountAlreadyLoggedIn, errAccountCreation, errAccountMustHoldNick, errAccountBadPassphrase, errCertfpAlreadyExists, errFeatureDisabled:
		message = err.Error()
	case errLimitExceeded:
		message = `There have been too many registration attempts recently; try again later`
	}
	return
}

// helper function to dispatch messages when a client successfully registers
func sendSuccessfulRegResponse(client *Client, rb *ResponseBuffer, forNS bool) {
	details := client.Details()
	if forNS {
		nsNotice(rb, client.t("Account created"))
	} else {
		rb.Add(nil, client.server.name, RPL_REG_SUCCESS, details.nick, details.accountName, client.t("Account created"))
	}
	client.server.snomasks.Send(sno.LocalAccounts, fmt.Sprintf(ircfmt.Unescape("Client $c[grey][$r%s$c[grey]] registered account $c[grey][$r%s$c[grey]]"), details.nickMask, details.accountName))
	sendSuccessfulAccountAuth(client, rb, forNS, false)
}

// sendSuccessfulAccountAuth means that an account auth attempt completed successfully, and is used to dispatch messages.
func sendSuccessfulAccountAuth(client *Client, rb *ResponseBuffer, forNS, forSASL bool) {
	details := client.Details()

	if forNS {
		nsNotice(rb, fmt.Sprintf(client.t("You're now logged in as %s"), details.accountName))
	} else {
		//TODO(dan): some servers send this numeric even for NickServ logins iirc? to confirm and maybe do too
		rb.Add(nil, client.server.name, RPL_LOGGEDIN, details.nick, details.nickMask, details.accountName, fmt.Sprintf(client.t("You are now logged in as %s"), details.accountName))
		if forSASL {
			rb.Add(nil, client.server.name, RPL_SASLSUCCESS, details.nick, client.t("Authentication successful"))
		}
	}

	// dispatch account-notify
	for friend := range client.Friends(caps.AccountNotify) {
		if friend != rb.session {
			friend.Send(nil, details.nickMask, "ACCOUNT", details.accountName)
		}
	}
	if rb.session.capabilities.Has(caps.AccountNotify) {
		rb.Add(nil, details.nickMask, "ACCOUNT", details.accountName)
	}

	client.server.snomasks.Send(sno.LocalAccounts, fmt.Sprintf(ircfmt.Unescape("Client $c[grey][$r%s$c[grey]] logged into account $c[grey][$r%s$c[grey]]"), details.nickMask, details.accountName))

	client.server.logger.Info("accounts", "client", details.nick, "logged into account", details.accountName)
}

// AUTHENTICATE [<mechanism>|<data>|*]
func authenticateHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	session := rb.session
	config := server.Config()
	details := client.Details()

	if client.isSTSOnly {
		rb.Add(nil, server.name, ERR_SASLFAIL, details.nick, client.t("SASL authentication failed"))
		return false
	}

	if details.account != "" {
		rb.Add(nil, server.name, ERR_SASLALREADY, details.nick, client.t("You're already logged into an account"))
		return false
	}

	// sasl abort
	if !config.Accounts.AuthenticationEnabled || len(msg.Params) == 1 && msg.Params[0] == "*" {
		rb.Add(nil, server.name, ERR_SASLABORTED, details.nick, client.t("SASL authentication aborted"))
		session.sasl.Clear()
		return false
	}

	// start new sasl session
	if session.sasl.mechanism == "" {
		mechanism := strings.ToUpper(msg.Params[0])
		_, mechanismIsEnabled := EnabledSaslMechanisms[mechanism]

		if mechanismIsEnabled {
			session.sasl.mechanism = mechanism
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
		session.sasl.Clear()
		return false
	} else if len(rawData) == 400 {
		// allow 4 'continuation' lines before rejecting for length
		if len(session.sasl.value) >= 400*4 {
			rb.Add(nil, server.name, ERR_SASLFAIL, details.nick, client.t("SASL authentication failed: Passphrase too long"))
			session.sasl.Clear()
			return false
		}
		session.sasl.value += rawData
		return false
	}
	if rawData != "+" {
		session.sasl.value += rawData
	}

	var data []byte
	var err error
	if session.sasl.value != "+" {
		data, err = base64.StdEncoding.DecodeString(session.sasl.value)
		if err != nil {
			rb.Add(nil, server.name, ERR_SASLFAIL, details.nick, client.t("SASL authentication failed: Invalid b64 encoding"))
			session.sasl.Clear()
			return false
		}
	}

	// call actual handler
	handler, handlerExists := EnabledSaslMechanisms[session.sasl.mechanism]

	// like 100% not required, but it's good to be safe I guess
	if !handlerExists {
		rb.Add(nil, server.name, ERR_SASLFAIL, details.nick, client.t("SASL authentication failed"))
		session.sasl.Clear()
		return false
	}

	// let the SASL handler do its thing
	exiting := handler(server, client, session.sasl.mechanism, data, rb)
	session.sasl.Clear()

	return exiting
}

// AUTHENTICATE PLAIN
func authPlainHandler(server *Server, client *Client, mechanism string, value []byte, rb *ResponseBuffer) bool {
	splitValue := bytes.Split(value, []byte{'\000'})

	// PLAIN has separate "authorization ID" (which user you want to become)
	// and "authentication ID" (whose password you want to use). the first is optional:
	// [authzid] \x00 authcid \x00 password
	var authzid, authcid string

	if len(splitValue) == 3 {
		authzid, authcid = string(splitValue[0]), string(splitValue[1])

		if authzid != "" && authcid != authzid {
			rb.Add(nil, server.name, ERR_SASLFAIL, client.Nick(), client.t("SASL authentication failed: authcid and authzid should be the same"))
			return false
		}
	} else {
		rb.Add(nil, server.name, ERR_SASLFAIL, client.Nick(), client.t("SASL authentication failed: Invalid auth blob"))
		return false
	}

	throttled, remainingTime := client.loginThrottle.Touch()
	if throttled {
		rb.Add(nil, server.name, ERR_SASLFAIL, client.Nick(), fmt.Sprintf(client.t("Please wait at least %v and try again"), remainingTime))
		return false
	}

	// see #843: strip the device ID for the benefit of clients that don't
	// distinguish user/ident from account name
	if strudelIndex := strings.IndexByte(authcid, '@'); strudelIndex != -1 {
		var deviceID string
		authcid, deviceID = authcid[:strudelIndex], authcid[strudelIndex+1:]
		if !client.registered {
			rb.session.deviceID = deviceID
		}
	}
	password := string(splitValue[2])
	err := server.accounts.AuthenticateByPassphrase(client, authcid, password)
	if err != nil {
		msg := authErrorToMessage(server, err)
		rb.Add(nil, server.name, ERR_SASLFAIL, client.Nick(), fmt.Sprintf("%s: %s", client.t("SASL authentication failed"), client.t(msg)))
		return false
	} else if !fixupNickEqualsAccount(client, rb, server.Config()) {
		return false
	}

	sendSuccessfulAccountAuth(client, rb, false, true)
	return false
}

func authErrorToMessage(server *Server, err error) (msg string) {
	if throttled, ok := err.(*ThrottleError); ok {
		return throttled.Error()
	}

	switch err {
	case errAccountDoesNotExist, errAccountUnverified, errAccountInvalidCredentials, errAuthzidAuthcidMismatch, errNickAccountMismatch:
		return err.Error()
	default:
		// don't expose arbitrary error messages to the user
		server.logger.Error("internal", "sasl authentication failure", err.Error())
		return "Unknown"
	}
}

// AUTHENTICATE EXTERNAL
func authExternalHandler(server *Server, client *Client, mechanism string, value []byte, rb *ResponseBuffer) bool {
	if rb.session.certfp == "" {
		rb.Add(nil, server.name, ERR_SASLFAIL, client.nick, client.t("SASL authentication failed, you are not connecting with a certificate"))
		return false
	}

	// EXTERNAL doesn't carry an authentication ID (this is determined from the
	// certificate), but does carry an optional authorization ID.
	var authzid string
	var err error
	if len(value) != 0 {
		authzid, err = CasefoldName(string(value))
		if err != nil {
			err = errAuthzidAuthcidMismatch
		}
	}

	if err == nil {
		// see #843: strip the device ID for the benefit of clients that don't
		// distinguish user/ident from account name
		if strudelIndex := strings.IndexByte(authzid, '@'); strudelIndex != -1 {
			var deviceID string
			authzid, deviceID = authzid[:strudelIndex], authzid[strudelIndex+1:]
			if !client.registered {
				rb.session.deviceID = deviceID
			}
		}
		err = server.accounts.AuthenticateByCertFP(client, rb.session.certfp, authzid)
	}

	if err != nil {
		msg := authErrorToMessage(server, err)
		rb.Add(nil, server.name, ERR_SASLFAIL, client.nick, fmt.Sprintf("%s: %s", client.t("SASL authentication failed"), client.t(msg)))
		return false
	} else if !fixupNickEqualsAccount(client, rb, server.Config()) {
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
		awayLen := server.Config().Limits.AwayLen
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

	dispatchAwayNotify(client, isAway, awayMessage)
	return false
}

func dispatchAwayNotify(client *Client, isAway bool, awayMessage string) {
	// dispatch away-notify
	details := client.Details()
	for session := range client.Friends(caps.AwayNotify) {
		if isAway {
			session.sendFromClientInternal(false, time.Time{}, "", details.nickMask, details.account, nil, "AWAY", awayMessage)
		} else {
			session.sendFromClientInternal(false, time.Time{}, "", details.nickMask, details.account, nil, "AWAY")
		}
	}
}

// BATCH {+,-}reference-tag type [params...]
func batchHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	tag := msg.Params[0]
	fail := false
	sendErrors := rb.session.batch.command != "NOTICE"
	if len(tag) == 0 {
		fail = true
	} else if tag[0] == '+' {
		if len(msg.Params) < 3 || msg.Params[1] != caps.MultilineBatchType {
			fail = true
		} else {
			err := rb.session.StartMultilineBatch(tag[1:], msg.Params[2], rb.Label, msg.ClientOnlyTags())
			fail = (err != nil)
			if !fail {
				// suppress ACK for the initial BATCH message (we'll apply the stored label later)
				rb.Label = ""
			}
		}
	} else if tag[0] == '-' {
		batch, err := rb.session.EndMultilineBatch(tag[1:])
		fail = (err != nil)
		if !fail {
			histType, err := msgCommandToHistType(batch.command)
			if err != nil {
				histType = history.Privmsg
				batch.command = "PRIVMSG"
			}
			// XXX changing the label inside a handler is a bit dodgy, but it works here
			// because there's no way we could have triggered a flush up to this point
			rb.Label = batch.responseLabel
			dispatchMessageToTarget(client, batch.tags, histType, batch.command, batch.target, batch.message, rb)
		}
	}

	if fail {
		rb.session.EndMultilineBatch("")
		if sendErrors {
			rb.Add(nil, server.name, "FAIL", "BATCH", "MULTILINE_INVALID", client.t("Invalid multiline batch"))
		}
	}

	return false
}

// BRB [message]
func brbHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	success, duration := client.brbTimer.Enable()
	if !success {
		rb.Add(nil, server.name, "FAIL", "BRB", "CANNOT_BRB", client.t("Your client does not support BRB"))
		return false
	} else {
		rb.Add(nil, server.name, "BRB", strconv.Itoa(int(duration.Seconds())))
	}

	var message string
	if 0 < len(msg.Params) {
		message = msg.Params[0]
	} else {
		message = client.t("I'll be right back")
	}

	if len(client.Sessions()) == 1 {
		// true BRB
		client.SetAway(true, message)
	}

	return true
}

// CAP <subcmd> [<caps>]
func capHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	details := client.Details()
	subCommand := strings.ToUpper(msg.Params[0])
	toAdd := caps.NewSet()
	toRemove := caps.NewSet()
	var capString string

	config := server.Config()
	supportedCaps := config.Server.supportedCaps
	if client.isSTSOnly {
		supportedCaps = stsOnlyCaps
	}

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
			if err != nil || (!remove && !supportedCaps.Has(capab)) {
				badCaps = true
			} else if !remove {
				toAdd.Enable(capab)
			} else {
				toRemove.Enable(capab)
			}
		}
	}

	sendCapLines := func(cset *caps.Set, values caps.Values) {
		version := rb.session.capVersion
		// we're working around two bugs:
		// 1. weechat 1.4 won't accept the CAP reply unless it contains the server.name source
		// 2. old versions of Kiwi and The Lounge can't parse multiline CAP LS 302 (#661),
		// so try as hard as possible to get the response to fit on one line.
		// :server.name CAP * LS * :<tokens>
		// 1           7         4
		maxLen := 510 - 1 - len(server.name) - 7 - len(subCommand) - 4
		capLines := cset.Strings(version, values, maxLen)
		for i, capStr := range capLines {
			if version >= caps.Cap302 && i < len(capLines)-1 {
				rb.Add(nil, server.name, "CAP", details.nick, subCommand, "*", capStr)
			} else {
				rb.Add(nil, server.name, "CAP", details.nick, subCommand, capStr)
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
		sendCapLines(supportedCaps, config.Server.capValues)

	case "LIST":
		// values not sent on LIST
		sendCapLines(&rb.session.capabilities, nil)

	case "REQ":
		if !client.registered {
			rb.session.capState = caps.NegotiatingState
		}

		// make sure all capabilities actually exist
		// #511, #521: oragono.io/nope is a fake cap to trap bad clients who blindly request
		// every offered capability. during registration, requesting it produces a quit,
		// otherwise just a CAP NAK
		if badCaps || (toAdd.Has(caps.Nope) && client.registered) {
			rb.Add(nil, server.name, "CAP", details.nick, "NAK", capString)
			return false
		} else if toAdd.Has(caps.Nope) && !client.registered {
			client.Quit(fmt.Sprintf(client.t("Requesting the %s client capability is forbidden"), caps.Nope.Name()), rb.session)
			return true
		}

		rb.session.capabilities.Union(toAdd)
		rb.session.capabilities.Subtract(toRemove)
		rb.Add(nil, server.name, "CAP", details.nick, "ACK", capString)

		// if this is the first time the client is requesting a resume token,
		// send it to them
		if toAdd.Has(caps.Resume) {
			token, id := server.resumeManager.GenerateToken(client)
			if token != "" {
				rb.Add(nil, server.name, "RESUME", "TOKEN", token)
				rb.session.SetResumeID(id)
			}
		}
	case "END":
		if !client.registered {
			rb.session.capState = caps.NegotiatedState
		}

	default:
		rb.Add(nil, server.name, ERR_INVALIDCAPCMD, details.nick, subCommand, client.t("Invalid CAP subcommand"))
	}
	return false
}

// CHATHISTORY <target> <preposition> <query> [<limit>]
// e.g., CHATHISTORY #ircv3 AFTER id=ytNBbt565yt4r3err3 10
// CHATHISTORY <target> BETWEEN <query> <query> <direction> [<limit>]
// e.g., CHATHISTORY #ircv3 BETWEEN timestamp=YYYY-MM-DDThh:mm:ss.sssZ timestamp=YYYY-MM-DDThh:mm:ss.sssZ + 100
func chathistoryHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) (exiting bool) {
	var items []history.Item
	unknown_command := false
	var target string
	var channel *Channel
	var sequence history.Sequence
	var err error
	defer func() {
		// successful responses are sent as a chathistory or history batch
		if err == nil {
			if channel != nil {
				channel.replayHistoryItems(rb, items, false)
			} else {
				client.replayPrivmsgHistory(rb, items, target, true)
			}
			return
		}

		// errors are sent either without a batch, or in a draft/labeled-response batch as usual
		if unknown_command {
			rb.Add(nil, server.name, "FAIL", "CHATHISTORY", "UNKNOWN_COMMAND", utils.SafeErrorParam(msg.Params[0]), client.t("Unknown command"))
		} else if err == utils.ErrInvalidParams {
			rb.Add(nil, server.name, "FAIL", "CHATHISTORY", "INVALID_PARAMETERS", msg.Params[0], client.t("Invalid parameters"))
		} else if err != nil {
			rb.Add(nil, server.name, "FAIL", "CHATHISTORY", "MESSAGE_ERROR", msg.Params[0], client.t("Messages could not be retrieved"))
		} else if sequence == nil {
			rb.Add(nil, server.name, "FAIL", "CHATHISTORY", "NO_SUCH_CHANNEL", utils.SafeErrorParam(msg.Params[1]), client.t("No such channel"))
		}
	}()

	config := server.Config()
	maxChathistoryLimit := config.History.ChathistoryMax
	if maxChathistoryLimit == 0 {
		return
	}
	preposition := strings.ToLower(msg.Params[0])
	target = msg.Params[1]

	parseQueryParam := func(param string) (msgid string, timestamp time.Time, err error) {
		if param == "*" && (preposition == "before" || preposition == "between") {
			// XXX compatibility with kiwi, which as of February 2020 is
			// using BEFORE * as a synonym for LATEST *
			return
		}
		err = utils.ErrInvalidParams
		pieces := strings.SplitN(param, "=", 2)
		if len(pieces) < 2 {
			return
		}
		identifier, value := strings.ToLower(pieces[0]), pieces[1]
		if identifier == "msgid" {
			msgid, err = value, nil
			return
		} else if identifier == "timestamp" {
			timestamp, err = time.Parse(IRCv3TimestampFormat, value)
			return
		}
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

	channel, sequence, err = server.GetHistorySequence(nil, client, target)
	if err != nil || sequence == nil {
		return
	}

	roundUp := func(endpoint time.Time) (result time.Time) {
		return endpoint.Truncate(time.Millisecond).Add(time.Millisecond)
	}

	var start, end history.Selector
	var limit int
	switch preposition {
	case "between":
		start.Msgid, start.Time, err = parseQueryParam(msg.Params[2])
		if err != nil {
			return
		}
		end.Msgid, end.Time, err = parseQueryParam(msg.Params[3])
		if err != nil {
			return
		}
		// XXX preserve the ordering of the two parameters, since we might be going backwards,
		// but round up the chronologically first one, whichever it is, to make it exclusive
		if !start.Time.IsZero() && !end.Time.IsZero() {
			if start.Time.Before(end.Time) {
				start.Time = roundUp(start.Time)
			} else {
				end.Time = roundUp(end.Time)
			}
		}
		limit = parseHistoryLimit(4)
	case "before", "after", "around":
		start.Msgid, start.Time, err = parseQueryParam(msg.Params[2])
		if err != nil {
			return
		}
		if preposition == "after" && !start.Time.IsZero() {
			start.Time = roundUp(start.Time)
		}
		if preposition == "before" {
			end = start
			start = history.Selector{}
		}
		limit = parseHistoryLimit(3)
	case "latest":
		if msg.Params[2] != "*" {
			end.Msgid, end.Time, err = parseQueryParam(msg.Params[2])
			if err != nil {
				return
			}
			if !end.Time.IsZero() {
				end.Time = roundUp(end.Time)
			}
			start.Time = time.Now().UTC()
		}
		limit = parseHistoryLimit(3)
	default:
		unknown_command = true
		return
	}

	if preposition == "around" {
		items, err = sequence.Around(start, limit)
	} else {
		items, _, err = sequence.Between(start, end, limit)
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
		profFile := server.Config().getOutputPath("oragono.mprof")
		file, err := os.Create(profFile)
		if err != nil {
			rb.Notice(fmt.Sprintf("error: %s", err))
			break
		}
		defer file.Close()
		pprof.Lookup("heap").WriteTo(file, 0)
		rb.Notice(fmt.Sprintf("written to %s", profFile))

	case "STARTCPUPROFILE":
		profFile := server.Config().getOutputPath("oragono.prof")
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

	case "CRASHSERVER":
		if !client.HasRoleCapabs("rehash") {
			rb.Notice(client.t("You must have rehash permissions in order to execute DEBUG CRASHSERVER"))
			return false
		}
		code := utils.ConfirmationCode(server.name, server.ctime)
		if len(msg.Params) == 1 || msg.Params[1] != code {
			rb.Notice(fmt.Sprintf(client.t("To confirm, run this command: %s"), fmt.Sprintf("/DEBUG CRASHSERVER %s", code)))
			return false
		}
		server.logger.Error("server", fmt.Sprintf("DEBUG CRASHSERVER executed by operator %s", client.Oper().Name))
		go func() {
			// intentional nil dereference on a new goroutine, bypassing recover-from-errors
			var i, j *int
			*i = *j
		}()

	default:
		rb.Notice(client.t("Unrecognized DEBUG subcommand"))
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
	if oper == nil || !oper.Class.Capabilities.Has("local_ban") {
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
			mcl.SetExitedSnomaskSent()
			mcl.Quit(fmt.Sprintf(mcl.t("You have been banned from this server (%s)"), reason), nil)
			if mcl == client {
				killClient = true
			} else {
				// if mcl == client, we kill them below
				mcl.destroy(nil)
			}
		}

		// send snomask
		sort.Strings(killedClientNicks)
		server.snomasks.Send(sno.LocalKills, fmt.Sprintf(ircfmt.Unescape("%s [%s] killed %d clients with a DLINE $c[grey][$r%s$c[grey]]"), client.nick, operName, len(killedClientNicks), strings.Join(killedClientNicks, ", ")))
	}

	return killClient
}

// EXTJWT <target> [service_name]
func extjwtHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	accountName := client.AccountName()
	if accountName == "*" {
		accountName = ""
	}

	claims := jwt.MapClaims{
		"iss":     server.name,
		"sub":     client.Nick(),
		"account": accountName,
		"umodes":  []string{},
	}

	if msg.Params[0] != "*" {
		channel := server.channels.Get(msg.Params[0])
		if channel == nil {
			rb.Add(nil, server.name, "FAIL", "EXTJWT", "NO_SUCH_CHANNEL", client.t("No such channel"))
			return false
		}

		claims["channel"] = channel.Name()
		claims["joined"] = 0
		claims["cmodes"] = []string{}
		if present, cModes := channel.ClientStatus(client); present {
			claims["joined"] = 1
			var modeStrings []string
			for _, cMode := range cModes {
				modeStrings = append(modeStrings, string(cMode))
			}
			claims["cmodes"] = modeStrings
		}
	}

	config := server.Config()
	var serviceName string
	var sConfig jwt.JwtServiceConfig
	if 1 < len(msg.Params) {
		serviceName = strings.ToLower(msg.Params[1])
		sConfig = config.Extjwt.Services[serviceName]
	} else {
		serviceName = "*"
		sConfig = config.Extjwt.Default
	}

	if !sConfig.Enabled() {
		rb.Add(nil, server.name, "FAIL", "EXTJWT", "NO_SUCH_SERVICE", client.t("No such service"))
		return false
	}

	tokenString, err := sConfig.Sign(claims)

	if err == nil {
		maxTokenLength := 400

		for maxTokenLength < len(tokenString) {
			rb.Add(nil, server.name, "EXTJWT", msg.Params[0], serviceName, "*", tokenString[:maxTokenLength])
			tokenString = tokenString[maxTokenLength:]
		}
		rb.Add(nil, server.name, "EXTJWT", msg.Params[0], serviceName, tokenString)
	} else {
		rb.Add(nil, server.name, "FAIL", "EXTJWT", "UNKNOWN_ERROR", client.t("Could not generate EXTJWT token"))
	}

	return false
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
			client.sendHelp(strings.ToUpper(argument), helpHandler.textGenerator(client), rb)
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
// HISTORY #darwin 1h
func historyHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	config := server.Config()
	if !config.History.Enabled {
		rb.Notice(client.t("This command has been disabled by the server administrators"))
		return false
	}

	items, channel, err := easySelectHistory(server, client, msg.Params)

	if err == errNoSuchChannel {
		rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.Nick(), utils.SafeErrorParam(msg.Params[0]), client.t("No such channel"))
		return false
	} else if err != nil {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.Nick(), msg.Command, client.t("Could not retrieve history"))
		return false
	}

	if len(items) != 0 {
		if channel != nil {
			channel.replayHistoryItems(rb, items, false)
		} else {
			client.replayPrivmsgHistory(rb, items, "", true)
		}
	}
	return false
}

// INFO
func infoHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	nick := client.Nick()
	// we do the below so that the human-readable lines in info can be translated.
	for _, line := range infoString1 {
		rb.Add(nil, server.name, RPL_INFO, nick, line)
	}
	rb.Add(nil, server.name, RPL_INFO, nick, fmt.Sprintf(client.t("This is Oragono version %s."), SemVer))
	if Commit != "" {
		rb.Add(nil, server.name, RPL_INFO, nick, fmt.Sprintf(client.t("It was built from git hash %s."), Commit))
	}
	rb.Add(nil, server.name, RPL_INFO, nick, "")
	rb.Add(nil, server.name, RPL_INFO, nick, client.t("Oragono is released under the MIT license."))
	rb.Add(nil, server.name, RPL_INFO, nick, "")
	rb.Add(nil, server.name, RPL_INFO, nick, client.t("Core Developers:"))
	for _, line := range infoString2 {
		rb.Add(nil, server.name, RPL_INFO, nick, line)
	}
	rb.Add(nil, server.name, RPL_INFO, nick, client.t("Former Core Developers:"))
	for _, line := range infoString3 {
		rb.Add(nil, server.name, RPL_INFO, nick, line)
	}
	rb.Add(nil, server.name, RPL_INFO, nick, client.t("For a more complete list of contributors, see our changelog:"))
	rb.Add(nil, server.name, RPL_INFO, nick, "    https://github.com/oragono/oragono/blob/master/CHANGELOG.md")
	rb.Add(nil, server.name, RPL_INFO, nick, "")
	// show translators for languages other than good ole' regular English
	tlines := server.Languages().Translators()
	if 0 < len(tlines) {
		rb.Add(nil, server.name, RPL_INFO, nick, client.t("Translators:"))
		for _, line := range tlines {
			rb.Add(nil, server.name, RPL_INFO, nick, "    "+strings.Replace(line, "\n", ", ", -1))
		}
		rb.Add(nil, server.name, RPL_INFO, nick, "")
	}
	rb.Add(nil, server.name, RPL_ENDOFINFO, nick, client.t("End of /INFO"))
	return false
}

// INVITE <nickname> <channel>
func inviteHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	nickname := msg.Params[0]
	channelName := msg.Params[1]

	target := server.clients.Get(nickname)
	if target == nil {
		rb.Add(nil, server.name, ERR_NOSUCHNICK, client.Nick(), utils.SafeErrorParam(nickname), client.t("No such nick"))
		return false
	}

	channel := server.channels.Get(channelName)
	if channel == nil {
		rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.Nick(), utils.SafeErrorParam(channelName), client.t("No such channel"))
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

	for i, name := range channels {
		if name == "" {
			continue // #679
		}
		var key string
		if len(keys) > i {
			key = keys[i]
		}
		err := server.channels.Join(client, name, key, false, rb)
		if err != nil {
			sendJoinError(client, name, rb, err)
		}
	}
	return false
}

func sendJoinError(client *Client, name string, rb *ResponseBuffer, err error) {
	var code, errMsg, forbiddingMode string
	switch err {
	case errInsufficientPrivs:
		code, errMsg = ERR_NOSUCHCHANNEL, `Only server operators can create new channels`
	case errConfusableIdentifier:
		code, errMsg = ERR_NOSUCHCHANNEL, `That channel name is too close to the name of another channel`
	case errChannelPurged:
		code, errMsg = ERR_NOSUCHCHANNEL, err.Error()
	case errTooManyChannels:
		code, errMsg = ERR_TOOMANYCHANNELS, `You have joined too many channels`
	case errLimitExceeded:
		code, forbiddingMode = ERR_CHANNELISFULL, "l"
	case errWrongChannelKey:
		code, forbiddingMode = ERR_BADCHANNELKEY, "k"
	case errInviteOnly:
		code, forbiddingMode = ERR_INVITEONLYCHAN, "i"
	case errBanned:
		code, forbiddingMode = ERR_BANNEDFROMCHAN, "b"
	case errRegisteredOnly:
		code, errMsg = ERR_NEEDREGGEDNICK, `You must be registered to join that channel`
	default:
		code, errMsg = ERR_NOSUCHCHANNEL, `No such channel`
	}
	if forbiddingMode != "" {
		errMsg = fmt.Sprintf(client.t("Cannot join channel (+%s)"), forbiddingMode)
	} else {
		errMsg = client.t(errMsg)
	}
	rb.Add(nil, client.server.name, code, client.Nick(), utils.SafeErrorParam(name), errMsg)
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
			rb.Add(nil, server.name, ERR_NEEDMOREPARAMS, client.Nick(), "SAJOIN", client.t("Not enough parameters"))
			return false
		} else {
			target = server.clients.Get(msg.Params[0])
			if target == nil {
				rb.Add(nil, server.name, ERR_NOSUCHNICK, client.Nick(), utils.SafeErrorParam(msg.Params[0]), "No such nick")
				return false
			}
			channelString = msg.Params[1]
		}
	}

	channels := strings.Split(channelString, ",")
	for _, chname := range channels {
		err := server.channels.Join(target, chname, "", true, rb)
		if err != nil {
			sendJoinError(client, chname, rb, err)
		}
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

	type kickCmd struct {
		channel string
		nick    string
	}
	kicks := make([]kickCmd, 0, len(channels))
	for index, channel := range channels {
		if channel == "" {
			continue // #679
		}
		if len(users) == 1 {
			kicks = append(kicks, kickCmd{channel, users[0]})
		} else {
			kicks = append(kicks, kickCmd{channel, users[index]})
		}
	}

	var comment string
	if len(msg.Params) > 2 {
		comment = msg.Params[2]
	}
	for _, kick := range kicks {
		channel := server.channels.Get(kick.channel)
		if channel == nil {
			rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, utils.SafeErrorParam(kick.channel), client.t("No such channel"))
			continue
		}

		target := server.clients.Get(kick.nick)
		if target == nil {
			rb.Add(nil, server.name, ERR_NOSUCHNICK, client.nick, utils.SafeErrorParam(kick.nick), client.t("No such nick"))
			continue
		}

		if comment == "" {
			comment = kick.nick
		}
		channel.Kick(client, target, comment, rb, false)
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

	target := server.clients.Get(nickname)
	if target == nil {
		rb.Add(nil, client.server.name, ERR_NOSUCHNICK, client.nick, utils.SafeErrorParam(nickname), client.t("No such nick"))
		return false
	}

	quitMsg := fmt.Sprintf("Killed (%s (%s))", client.nick, comment)

	server.snomasks.Send(sno.LocalKills, fmt.Sprintf(ircfmt.Unescape("%s$r was killed by %s $c[grey][$r%s$c[grey]]"), target.nick, client.nick, comment))
	target.SetExitedSnomaskSent()

	target.Quit(quitMsg, nil)
	target.destroy(nil)
	return false
}

// KLINE [ANDKILL] [MYSELF] [duration] <mask> [ON <server>] [reason [| oper reason]]
// KLINE LIST
func klineHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	details := client.Details()
	// check oper permissions
	oper := client.Oper()
	if oper == nil || !oper.Class.Capabilities.Has("local_ban") {
		rb.Add(nil, server.name, ERR_NOPRIVS, details.nick, msg.Command, client.t("Insufficient oper privs"))
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
		rb.Add(nil, server.name, ERR_NEEDMOREPARAMS, details.nick, msg.Command, client.t("Not enough parameters"))
		return false
	}
	mask := msg.Params[currentArg]
	currentArg++

	// check mask
	mask, err = CanonicalizeMaskWildcard(mask)
	if err != nil {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, details.nick, msg.Command, client.t("Erroneous nickname"))
		return false
	}

	matcher, err := utils.CompileGlob(mask, false)
	if err != nil {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, details.nick, msg.Command, client.t("Erroneous nickname"))
		return false
	}

	for _, clientMask := range client.AllNickmasks() {
		if !klineMyself && matcher.MatchString(clientMask) {
			rb.Add(nil, server.name, ERR_UNKNOWNERROR, details.nick, msg.Command, client.t("This ban matches you. To KLINE yourself, you must use the command:  /KLINE MYSELF <arguments>"))
			return false
		}
	}

	// check remote
	if len(msg.Params) > currentArg && msg.Params[currentArg] == "ON" {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, details.nick, msg.Command, client.t("Remote servers not yet supported"))
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
		snoDescription = fmt.Sprintf(ircfmt.Unescape("%s [%s]$r added temporary (%s) K-Line for %s"), details.nick, operName, duration.String(), mask)
	} else {
		rb.Notice(fmt.Sprintf(client.t("Added K-Line for %s"), mask))
		snoDescription = fmt.Sprintf(ircfmt.Unescape("%s [%s]$r added K-Line for %s"), details.nick, operName, mask)
	}
	server.snomasks.Send(sno.LocalXline, snoDescription)

	var killClient bool
	if andKill {
		var clientsToKill []*Client
		var killedClientNicks []string

		for _, mcl := range server.clients.AllClients() {
			for _, clientMask := range mcl.AllNickmasks() {
				if matcher.MatchString(clientMask) {
					clientsToKill = append(clientsToKill, mcl)
					killedClientNicks = append(killedClientNicks, mcl.nick)
				}
			}
		}

		for _, mcl := range clientsToKill {
			mcl.SetExitedSnomaskSent()
			mcl.Quit(fmt.Sprintf(mcl.t("You have been banned from this server (%s)"), reason), nil)
			if mcl == client {
				killClient = true
			} else {
				// if mcl == client, we kill them below
				mcl.destroy(nil)
			}
		}

		// send snomask
		sort.Strings(killedClientNicks)
		server.snomasks.Send(sno.LocalKills, fmt.Sprintf(ircfmt.Unescape("%s [%s] killed %d clients with a KLINE $c[grey][$r%s$c[grey]]"), details.nick, operName, len(killedClientNicks), strings.Join(killedClientNicks, ", ")))
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
	config := server.Config()
	if time.Since(client.ctime) < config.Channels.ListDelay && client.Account() == "" && !client.HasMode(modes.Operator) {
		remaining := time.Until(client.ctime.Add(config.Channels.ListDelay))
		csNotice(rb, fmt.Sprintf(client.t("This server requires that you wait %v after connecting before you can use /LIST. You have %v left."), config.Channels.ListDelay, remaining))
		rb.Add(nil, server.name, RPL_LISTEND, client.Nick(), client.t("End of LIST"))
		return false
	}

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

	nick := client.Nick()
	rplList := func(channel *Channel) {
		if members, name, topic := channel.listData(); members != 0 {
			rb.Add(nil, client.server.name, RPL_LIST, nick, name, strconv.Itoa(members), topic)
		}
	}

	clientIsOp := client.HasMode(modes.Operator)
	if len(channels) == 0 {
		for _, channel := range server.channels.Channels() {
			if !clientIsOp && channel.flags.HasMode(modes.Secret) {
				continue
			}
			if matcher.Matches(channel) {
				rplList(channel)
			}
		}
	} else {
		// limit regular users to only listing one channel
		if !clientIsOp {
			channels = channels[:1]
		}

		for _, chname := range channels {
			channel := server.channels.Get(chname)
			if channel == nil || (!clientIsOp && channel.flags.HasMode(modes.Secret)) {
				if len(chname) > 0 {
					rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, utils.SafeErrorParam(chname), client.t("No such channel"))
				}
				continue
			}
			if matcher.Matches(channel) {
				rplList(channel)
			}
		}
	}
	rb.Add(nil, server.name, RPL_LISTEND, client.nick, client.t("End of LIST"))
	return false
}

// LUSERS [<mask> [<server>]]
func lusersHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	server.Lusers(client, rb)
	return false
}

// MODE <target> [<modestring> [<mode arguments>...]]
func modeHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	if 0 < len(msg.Params[0]) && msg.Params[0][0] == '#' {
		return cmodeHandler(server, client, msg, rb)
	}
	return umodeHandler(server, client, msg, rb)
}

// MODE <channel> [<modestring> [<mode arguments>...]]
func cmodeHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	channel := server.channels.Get(msg.Params[0])

	if channel == nil {
		rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, utils.SafeErrorParam(msg.Params[0]), client.t("No such channel"))
		return false
	}

	var changes modes.ModeChanges
	if 1 < len(msg.Params) {
		// parse out real mode changes
		params := msg.Params[1:]
		var unknown map[rune]bool
		changes, unknown = modes.ParseChannelModeChanges(params...)

		// alert for unknown mode changes
		for char := range unknown {
			rb.Add(nil, server.name, ERR_UNKNOWNMODE, client.nick, string(char), client.t("is an unknown mode character to me"))
		}
		if len(unknown) == 1 && len(changes) == 0 {
			return false
		}
	}
	// process mode changes, include list operations (an empty set of changes does a list)
	applied := channel.ApplyChannelModeChanges(client, msg.Command == "SAMODE", changes, rb)
	details := client.Details()
	announceCmodeChanges(channel, applied, details.nickMask, details.accountName, details.account, rb)

	return false
}

func announceCmodeChanges(channel *Channel, applied modes.ModeChanges, source, accountName, account string, rb *ResponseBuffer) {
	// send out changes
	if len(applied) > 0 {
		message := utils.MakeMessage("")
		changeStrings := applied.Strings()
		for _, changeString := range changeStrings {
			message.Split = append(message.Split, utils.MessagePair{Message: changeString})
		}
		args := append([]string{channel.name}, changeStrings...)
		rb.AddFromClient(message.Time, message.Msgid, source, accountName, nil, "MODE", args...)
		for _, member := range channel.Members() {
			for _, session := range member.Sessions() {
				if session != rb.session {
					session.sendFromClientInternal(false, message.Time, message.Msgid, source, accountName, nil, "MODE", args...)
				}
			}
		}
		channel.AddHistoryItem(history.Item{
			Type:        history.Mode,
			Nick:        source,
			AccountName: accountName,
			Message:     message,
		}, account)
	}
}

// MODE <client> [<modestring> [<mode arguments>...]]
func umodeHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	cDetails := client.Details()
	target := server.clients.Get(msg.Params[0])
	if target == nil {
		rb.Add(nil, server.name, ERR_NOSUCHNICK, cDetails.nick, utils.SafeErrorParam(msg.Params[0]), client.t("No such nick"))
		return false
	}

	targetNick := target.Nick()
	hasPrivs := client == target || msg.Command == "SAMODE"

	if !hasPrivs {
		if len(msg.Params) > 1 {
			rb.Add(nil, server.name, ERR_USERSDONTMATCH, cDetails.nick, client.t("Can't change modes for other users"))
		} else {
			rb.Add(nil, server.name, ERR_USERSDONTMATCH, cDetails.nick, client.t("Can't view modes for other users"))
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
			rb.Add(nil, server.name, ERR_UNKNOWNMODE, cDetails.nick, string(char), client.t("is an unknown mode character to me"))
		}
		if len(unknown) == 1 && len(changes) == 0 {
			return false
		}

		// apply mode changes
		applied = ApplyUserModeChanges(target, changes, msg.Command == "SAMODE", nil)
	}

	if len(applied) > 0 {
		args := append([]string{targetNick}, applied.Strings()...)
		rb.Add(nil, cDetails.nickMask, "MODE", args...)
	} else if hasPrivs {
		rb.Add(nil, server.name, RPL_UMODEIS, targetNick, target.ModeString())
		if target.HasMode(modes.LocalOperator) || target.HasMode(modes.Operator) {
			masks := server.snomasks.String(target)
			if 0 < len(masks) {
				rb.Add(nil, server.name, RPL_SNOMASKIS, targetNick, masks, client.t("Server notice masks"))
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
		server.monitorManager.Remove(rb.session, target)
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

	limits := server.Config().Limits

	targets := strings.Split(msg.Params[1], ",")
	for _, target := range targets {
		// check name length
		if len(target) < 1 || len(targets) > limits.NickLen {
			continue
		}

		// add target
		err := server.monitorManager.Add(rb.session, target, limits.MonitorEntries)
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
	server.monitorManager.RemoveAll(rb.session)
	return false
}

// MONITOR L
func monitorListHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	nick := client.Nick()
	monitorList := server.monitorManager.List(rb.session)

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

	monitorList := server.monitorManager.List(rb.session)

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

	// implement the modern behavior: https://modern.ircdocs.horse/#names-message
	// "Servers MAY only return information about the first <channel> and silently ignore the others."
	// "If no parameter is given for this command, servers SHOULD return one RPL_ENDOFNAMES numeric
	//  with the <channel> parameter set to an asterix character"

	if len(channels) == 0 {
		rb.Add(nil, server.name, RPL_ENDOFNAMES, client.Nick(), "*", client.t("End of NAMES list"))
		return false
	}

	chname := channels[0]
	success := false
	channel := server.channels.Get(chname)
	if channel != nil {
		if !channel.flags.HasMode(modes.Secret) || channel.hasClient(client) || client.HasMode(modes.Operator) {
			channel.Names(client, rb)
			success = true
		}
	}
	if !success { // channel.Names() sends this numeric itself on success
		rb.Add(nil, server.name, RPL_ENDOFNAMES, client.Nick(), chname, client.t("End of NAMES list"))
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

// helper to store a batched PRIVMSG in the session object
func absorbBatchedMessage(server *Server, client *Client, msg ircmsg.IrcMessage, batchTag string, histType history.ItemType, rb *ResponseBuffer) {
	var errorCode, errorMessage string
	defer func() {
		if errorCode != "" {
			if histType != history.Notice {
				rb.Add(nil, server.name, "FAIL", "BATCH", errorCode, errorMessage)
			}
			rb.session.EndMultilineBatch("")
		}
	}()

	if batchTag != rb.session.batch.label {
		errorCode, errorMessage = "MULTILINE_INVALID", client.t("Incorrect batch tag sent")
		return
	} else if len(msg.Params) < 2 {
		errorCode, errorMessage = "MULTILINE_INVALID", client.t("Invalid multiline batch")
		return
	}
	rb.session.batch.command = msg.Command
	isConcat, _ := msg.GetTag(caps.MultilineConcatTag)
	if isConcat && len(msg.Params[1]) == 0 {
		errorCode, errorMessage = "MULTILINE_INVALID", client.t("Cannot send a blank line with the multiline concat tag")
		return
	}
	if !isConcat && len(rb.session.batch.message.Split) != 0 {
		rb.session.batch.lenBytes++ // bill for the newline
	}
	rb.session.batch.message.Append(msg.Params[1], isConcat)
	rb.session.batch.lenBytes += len(msg.Params[1])
	config := server.Config()
	if config.Limits.Multiline.MaxBytes < rb.session.batch.lenBytes {
		errorCode, errorMessage = "MULTILINE_MAX_BYTES", strconv.Itoa(config.Limits.Multiline.MaxBytes)
	} else if config.Limits.Multiline.MaxLines != 0 && config.Limits.Multiline.MaxLines < rb.session.batch.message.LenLines() {
		errorCode, errorMessage = "MULTILINE_MAX_LINES", strconv.Itoa(config.Limits.Multiline.MaxLines)
	}
}

// NOTICE <target>{,<target>} <message>
// PRIVMSG <target>{,<target>} <message>
// TAGMSG <target>{,<target>}
func messageHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	histType, err := msgCommandToHistType(msg.Command)
	if err != nil {
		return false
	}

	if isBatched, batchTag := msg.GetTag("batch"); isBatched {
		absorbBatchedMessage(server, client, msg, batchTag, histType, rb)
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
	if histType != history.Tagmsg && message == "" {
		rb.Add(nil, server.name, ERR_NOTEXTTOSEND, cnick, client.t("No text to send"))
		return false
	}

	isCTCP := utils.IsRestrictedCTCPMessage(message)
	if histType == history.Privmsg && !isCTCP {
		client.UpdateActive(rb.session)
	}

	if rb.session.isTor && isCTCP {
		// note that error replies are never sent for NOTICE
		if histType != history.Notice {
			rb.Notice(client.t("CTCP messages are disabled over Tor"))
		}
		return false
	}

	for i, targetString := range targets {
		// max of four targets per privmsg
		if i == maxTargets {
			break
		}
		// each target gets distinct msgids
		splitMsg := utils.MakeMessage(message)
		dispatchMessageToTarget(client, clientOnlyTags, histType, msg.Command, targetString, splitMsg, rb)
	}
	return false
}

func dispatchMessageToTarget(client *Client, tags map[string]string, histType history.ItemType, command, target string, message utils.SplitMessage, rb *ResponseBuffer) {
	server := client.server

	prefixes, target := modes.SplitChannelMembershipPrefixes(target)
	lowestPrefix := modes.GetLowestChannelModePrefix(prefixes)

	if len(target) == 0 {
		return
	} else if target[0] == '#' {
		channel := server.channels.Get(target)
		if channel == nil {
			if histType != history.Notice {
				rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.Nick(), utils.SafeErrorParam(target), client.t("No such channel"))
			}
			return
		}
		channel.SendSplitMessage(command, lowestPrefix, tags, client, message, rb)
	} else {
		lowercaseTarget := strings.ToLower(target)
		service, isService := OragonoServices[lowercaseTarget]
		_, isZNC := zncHandlers[lowercaseTarget]

		if histType == history.Privmsg {
			if isService {
				servicePrivmsgHandler(service, server, client, message.Message, rb)
				return
			} else if isZNC {
				zncPrivmsgHandler(client, lowercaseTarget, message.Message, rb)
				return
			}
		}

		// NOTICE and TAGMSG to services are ignored
		if isService || isZNC {
			return
		}

		user := server.clients.Get(target)
		if user == nil {
			if histType != history.Notice {
				rb.Add(nil, server.name, ERR_NOSUCHNICK, client.Nick(), target, "No such nick")
			}
			return
		}

		// Restrict CTCP message for target user with +T
		if user.modes.HasMode(modes.UserNoCTCP) && message.IsRestrictedCTCPMessage() {
			return
		}

		tDetails := user.Details()
		tnick := tDetails.nick

		details := client.Details()
		nickMaskString := details.nickMask
		accountName := details.accountName
		var deliverySessions []*Session
		// restrict messages appropriately when +R is set
		// intentionally make the sending user think the message went through fine
		allowedPlusR := details.account != "" || !user.HasMode(modes.RegisteredOnly)
		if allowedPlusR {
			deliverySessions = append(deliverySessions, user.Sessions()...)
		}
		// all sessions of the sender, except the originating session, get a copy as well:
		if client != user {
			for _, session := range client.Sessions() {
				if session != rb.session {
					deliverySessions = append(deliverySessions, session)
				}
			}
		}

		for _, session := range deliverySessions {
			hasTagsCap := session.capabilities.Has(caps.MessageTags)
			// don't send TAGMSG at all if they don't have the tags cap
			if histType == history.Tagmsg && hasTagsCap {
				session.sendFromClientInternal(false, message.Time, message.Msgid, nickMaskString, accountName, tags, command, tnick)
			} else if histType != history.Tagmsg && !(session.isTor && message.IsRestrictedCTCPMessage()) {
				tagsToSend := tags
				if !hasTagsCap {
					tagsToSend = nil
				}
				session.sendSplitMsgFromClientInternal(false, nickMaskString, accountName, tagsToSend, command, tnick, message)
			}
		}

		// the originating session may get an echo message:
		if rb.session.capabilities.Has(caps.EchoMessage) {
			hasTagsCap := rb.session.capabilities.Has(caps.MessageTags)
			if histType == history.Tagmsg && hasTagsCap {
				rb.AddFromClient(message.Time, message.Msgid, nickMaskString, accountName, tags, command, tnick)
			} else {
				tagsToSend := tags
				if !hasTagsCap {
					tagsToSend = nil
				}
				rb.AddSplitMessageFromClient(nickMaskString, accountName, tagsToSend, command, tnick, message)
			}
		}
		if histType != history.Notice && user.Away() {
			//TODO(dan): possibly implement cooldown of away notifications to users
			rb.Add(nil, server.name, RPL_AWAY, client.Nick(), tnick, user.AwayMessage())
		}

		config := server.Config()
		if !config.History.Enabled {
			return
		}
		item := history.Item{
			Type:        histType,
			Message:     message,
			Nick:        nickMaskString,
			AccountName: accountName,
			Tags:        tags,
		}
		if !item.IsStorable() || !allowedPlusR {
			return
		}
		targetedItem := item
		targetedItem.Params[0] = tnick
		cStatus, _ := client.historyStatus(config)
		tStatus, _ := user.historyStatus(config)
		// add to ephemeral history
		if cStatus == HistoryEphemeral {
			targetedItem.CfCorrespondent = tDetails.nickCasefolded
			client.history.Add(targetedItem)
		}
		if tStatus == HistoryEphemeral && client != user {
			item.CfCorrespondent = details.nickCasefolded
			user.history.Add(item)
		}
		if cStatus == HistoryPersistent || tStatus == HistoryPersistent {
			targetedItem.CfCorrespondent = ""
			server.historyDB.AddDirectMessage(details.nickCasefolded, details.account, tDetails.nickCasefolded, tDetails.account, targetedItem)
		}
	}
}

// NPC <target> <sourcenick> <message>
func npcHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	target := msg.Params[0]
	fakeSource := msg.Params[1]
	message := msg.Params[2:]

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
	message := msg.Params[2:]
	sourceString := fmt.Sprintf(npcNickMask, fakeSource, client.nick)

	_, err := CasefoldName(fakeSource)
	if err != nil {
		client.Send(nil, client.server.name, ERR_CANNOTSENDRP, target, client.t("Fake source must be a valid nickname"))
		return false
	}

	sendRoleplayMessage(server, client, sourceString, target, true, message, rb)

	return false
}

// OPER <name> [password]
func operHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	if client.HasMode(modes.Operator) {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.Nick(), "OPER", client.t("You're already opered-up!"))
		return false
	}

	// must pass at least one check, and all enabled checks
	var checkPassed, checkFailed, passwordFailed bool
	oper := server.GetOperator(msg.Params[0])
	if oper != nil {
		if oper.Certfp != "" {
			if oper.Certfp == rb.session.certfp {
				checkPassed = true
			} else {
				checkFailed = true
			}
		}
		if !checkFailed && oper.Pass != nil {
			if len(msg.Params) == 1 {
				checkFailed = true
			} else if bcrypt.CompareHashAndPassword(oper.Pass, []byte(msg.Params[1])) != nil {
				checkFailed = true
				passwordFailed = true
			} else {
				checkPassed = true
			}
		}
	}

	if !checkPassed || checkFailed {
		rb.Add(nil, server.name, ERR_PASSWDMISMATCH, client.Nick(), client.t("Password incorrect"))
		// #951: only disconnect them if we actually tried to check a password for them
		if passwordFailed {
			client.Quit(client.t("Password incorrect"), rb.session)
			return true
		} else {
			return false
		}
	}

	if oper != nil {
		applyOper(client, oper, rb)
	}
	return false
}

// adds or removes operator status
// XXX: to add oper, this calls into ApplyUserModeChanges, but to remove oper,
// ApplyUserModeChanges calls into this, because the commands are asymmetric
// (/OPER to add, /MODE self -o to remove)
func applyOper(client *Client, oper *Oper, rb *ResponseBuffer) {
	details := client.Details()
	client.SetOper(oper)
	newDetails := client.Details()
	if details.nickMask != newDetails.nickMask {
		client.sendChghost(details.nickMask, newDetails.hostname)
	}

	if oper != nil {
		// set new modes: modes.Operator, plus anything specified in the config
		modeChanges := make([]modes.ModeChange, len(oper.Modes)+1)
		modeChanges[0] = modes.ModeChange{
			Mode: modes.Operator,
			Op:   modes.Add,
		}
		copy(modeChanges[1:], oper.Modes)
		applied := ApplyUserModeChanges(client, modeChanges, true, oper)

		client.server.snomasks.Send(sno.LocalOpers, fmt.Sprintf(ircfmt.Unescape("Client opered up $c[grey][$r%s$c[grey], $r%s$c[grey]]"), newDetails.nickMask, oper.Name))

		rb.Broadcast(nil, client.server.name, RPL_YOUREOPER, details.nick, client.t("You are now an IRC operator"))
		args := append([]string{details.nick}, applied.Strings()...)
		rb.Broadcast(nil, client.server.name, "MODE", args...)
	} else {
		client.server.snomasks.Send(sno.LocalOpers, fmt.Sprintf(ircfmt.Unescape("Client deopered $c[grey][$r%s$c[grey]]"), newDetails.nickMask))
	}

	for _, session := range client.Sessions() {
		// client may now be unthrottled by the fakelag system
		session.resetFakelag()
	}
}

// DEOPER
func deoperHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	// pretend they sent /MODE $nick -o
	fakeModeMsg := ircmsg.MakeMessage(nil, "", "MODE", client.Nick(), "-o")
	return umodeHandler(server, client, fakeModeMsg, rb)
}

// PART <channel>{,<channel>} [<reason>]
func partHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	channels := strings.Split(msg.Params[0], ",")
	var reason string
	if len(msg.Params) > 1 {
		reason = msg.Params[1]
	}

	for _, chname := range channels {
		if chname == "" {
			continue // #679
		}
		err := server.channels.Part(client, chname, reason, rb)
		if err == errNoSuchChannel {
			rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, utils.SafeErrorParam(chname), client.t("No such channel"))
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
	// only give them one try to run the PASS command (if a server password is set,
	// then all code paths end with this variable being set):
	if rb.session.passStatus != serverPassUnsent {
		return false
	}

	password := msg.Params[0]
	config := server.Config()

	if config.Accounts.LoginViaPassCommand {
		colonIndex := strings.IndexByte(password, ':')
		if colonIndex != -1 && client.Account() == "" {
			account, accountPass := password[:colonIndex], password[colonIndex+1:]
			if strudelIndex := strings.IndexByte(account, '@'); strudelIndex != -1 {
				account, rb.session.deviceID = account[:strudelIndex], account[strudelIndex+1:]
			}
			err := server.accounts.AuthenticateByPassphrase(client, account, accountPass)
			if err == nil {
				sendSuccessfulAccountAuth(client, rb, false, true)
				// login-via-pass-command entails that we do not need to check
				// an actual server password (either no password or skip-server-password)
				rb.session.passStatus = serverPassSuccessful
				return false
			}
		}
	}
	// if login-via-PASS failed for any reason, proceed to try and interpret the
	// provided password as the server password

	serverPassword := config.Server.passwordBytes

	// if no password exists, skip checking
	if serverPassword == nil {
		return false
	}

	// check the provided password
	if bcrypt.CompareHashAndPassword(serverPassword, []byte(password)) == nil {
		rb.session.passStatus = serverPassSuccessful
	} else {
		rb.session.passStatus = serverPassFailed
	}

	// if they failed the check, we'll bounce them later when they try to complete registration
	// note in particular that with skip-server-password, you can give the wrong server
	// password here, then successfully SASL and be admitted
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
	nick := client.Nick()
	server.logger.Info("server", "REHASH command used by", nick)
	err := server.rehash()

	if err == nil {
		// we used to send RPL_REHASHING here but i don't think it really makes sense
		// in the labeled-response world, since the intent is "rehash in progress" but
		// it won't display until the rehash is actually complete
		// TODO all operators should get a notice of some kind here
		rb.Notice(client.t("Rehash complete"))
	} else {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, nick, "REHASH", err.Error())
	}
	return false
}

// RENAME <oldchan> <newchan> [<reason>]
func renameHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) (result bool) {
	result = false
	oldName, newName := msg.Params[0], msg.Params[1]
	var reason string
	if 2 < len(msg.Params) {
		reason = msg.Params[2]
	}

	channel := server.channels.Get(oldName)
	if channel == nil {
		rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.Nick(), utils.SafeErrorParam(oldName), client.t("No such channel"))
		return false
	}
	if !(channel.ClientIsAtLeast(client, modes.ChannelOperator) || client.HasRoleCapabs("chanreg")) {
		rb.Add(nil, server.name, ERR_CHANOPRIVSNEEDED, client.Nick(), oldName, client.t("You're not a channel operator"))
		return false
	}

	founder := channel.Founder()
	if founder != "" && founder != client.Account() {
		rb.Add(nil, server.name, ERR_CANNOTRENAME, client.Nick(), oldName, newName, client.t("Only channel founders can change registered channels"))
		return false
	}

	config := server.Config()
	status, _ := channel.historyStatus(config)
	if status == HistoryPersistent {
		rb.Add(nil, server.name, ERR_CANNOTRENAME, client.Nick(), oldName, newName, client.t("Channels with persistent history cannot be renamed"))
		return false
	}

	// perform the channel rename
	err := server.channels.Rename(oldName, newName)
	if err == errInvalidChannelName {
		rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.Nick(), utils.SafeErrorParam(newName), client.t(err.Error()))
	} else if err == errChannelNameInUse {
		rb.Add(nil, server.name, ERR_CHANNAMEINUSE, client.Nick(), utils.SafeErrorParam(newName), client.t(err.Error()))
	} else if err != nil {
		rb.Add(nil, server.name, ERR_CANNOTRENAME, client.Nick(), oldName, utils.SafeErrorParam(newName), client.t("Cannot rename channel"))
	}
	if err != nil {
		return false
	}

	// send RENAME messages
	clientPrefix := client.NickMaskString()
	for _, mcl := range channel.Members() {
		mDetails := mcl.Details()
		for _, mSession := range mcl.Sessions() {
			targetRb := rb
			targetPrefix := clientPrefix
			if mSession != rb.session {
				targetRb = NewResponseBuffer(mSession)
				targetPrefix = mDetails.nickMask
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
					targetRb.Add(nil, targetPrefix, "PART", oldName, mcl.t("Channel renamed"))
				}
				if mSession.capabilities.Has(caps.ExtendedJoin) {
					targetRb.Add(nil, targetPrefix, "JOIN", newName, mDetails.accountName, mDetails.realname)
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
	details := ResumeDetails{
		PresentedToken: msg.Params[0],
	}

	if client.registered {
		rb.Add(nil, server.name, "FAIL", "RESUME", "REGISTRATION_IS_COMPLETED", client.t("Cannot resume connection, connection registration has already been completed"))
		return false
	}

	if 1 < len(msg.Params) {
		ts, err := time.Parse(IRCv3TimestampFormat, msg.Params[1])
		if err == nil {
			details.Timestamp = ts
		} else {
			rb.Add(nil, server.name, "WARN", "RESUME", "HISTORY_LOST", client.t("Timestamp is not in 2006-01-02T15:04:05.999Z format, ignoring it"))
		}
	}

	rb.session.resumeDetails = &details
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
	message := msg.Params[1:]
	sourceString := fmt.Sprintf(sceneNickMask, client.nick)

	sendRoleplayMessage(server, client, sourceString, target, false, message, rb)

	return false
}

// SETNAME <realname>
func setnameHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	realname := msg.Params[0]
	client.SetRealname(realname)
	details := client.Details()

	// alert friends
	now := time.Now().UTC()
	for session := range client.Friends(caps.SetName) {
		session.sendFromClientInternal(false, now, "", details.nickMask, details.account, nil, "SETNAME", details.realname)
	}

	return false
}

// SUMMON [parameters]
func summonHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	rb.Add(nil, server.name, ERR_SUMMONDISABLED, client.Nick(), client.t("SUMMON has been disabled"))
	return false
}

// TIME
func timeHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	rb.Add(nil, server.name, RPL_TIME, client.nick, server.name, time.Now().UTC().Format(time.RFC1123))
	return false
}

// TOPIC <channel> [<topic>]
func topicHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	channel := server.channels.Get(msg.Params[0])
	if channel == nil {
		rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, utils.SafeErrorParam(msg.Params[0]), client.t("No such channel"))
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
	if oper == nil || !oper.Class.Capabilities.Has("local_unban") {
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
	details := client.Details()
	// check oper permissions
	oper := client.Oper()
	if oper == nil || !oper.Class.Capabilities.Has("local_unban") {
		rb.Add(nil, server.name, ERR_NOPRIVS, details.nick, msg.Command, client.t("Insufficient oper privs"))
		return false
	}

	// get host
	mask := msg.Params[0]
	mask, err := CanonicalizeMaskWildcard(mask)
	if err != nil {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, details.nick, msg.Command, client.t("Erroneous nickname"))
		return false
	}

	err = server.klines.RemoveMask(mask)

	if err != nil {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, details.nick, msg.Command, fmt.Sprintf(client.t("Could not remove ban [%s]"), err.Error()))
		return false
	}

	rb.Notice(fmt.Sprintf(client.t("Removed K-Line for %s"), mask))
	server.snomasks.Send(sno.LocalXline, fmt.Sprintf(ircfmt.Unescape("%s$r removed K-Line for %s"), details.nick, mask))
	return false
}

// USER <username> * 0 <realname>
func userHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	if client.registered {
		rb.Add(nil, server.name, ERR_ALREADYREGISTRED, client.Nick(), client.t("You may not reregister"))
		return false
	}

	username, realname := msg.Params[0], msg.Params[3]
	if len(realname) == 0 {
		rb.Add(nil, server.name, ERR_NEEDMOREPARAMS, client.Nick(), client.t("Not enough parameters"))
		return false
	}

	// #843: we accept either: `USER user:pass@clientid` or `USER user@clientid`
	if strudelIndex := strings.IndexByte(username, '@'); strudelIndex != -1 {
		username, rb.session.deviceID = username[:strudelIndex], username[strudelIndex+1:]
		if colonIndex := strings.IndexByte(username, ':'); colonIndex != -1 {
			var password string
			username, password = username[:colonIndex], username[colonIndex+1:]
			err := server.accounts.AuthenticateByPassphrase(client, username, password)
			if err == nil {
				sendSuccessfulAccountAuth(client, rb, false, true)
			} else {
				// this is wrong, but send something for debugging that will show up in a raw transcript
				rb.Add(nil, server.name, ERR_SASLFAIL, client.Nick(), client.t("SASL authentication failed"))
			}
		}
	}

	err := client.SetNames(username, realname, false)
	if err == errInvalidUsername {
		// if client's using a unicode nick or something weird, let's just set 'em up with a stock username instead.
		// fixes clients that just use their nick as a username so they can still use the interesting nick
		if client.preregNick == username {
			client.SetNames("user", realname, false)
		} else {
			rb.Add(nil, server.name, ERR_INVALIDUSERNAME, client.Nick(), client.t("Malformed username"))
		}
	}

	return false
}

// USERHOST <nickname>{ <nickname>}
func userhostHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	returnedClients := make(ClientSet)

	var tl utils.TokenLineBuilder
	tl.Initialize(400, " ")
	for i, nickname := range msg.Params {
		if i >= 10 {
			break
		}

		target := server.clients.Get(nickname)
		if target == nil {
			continue
		}
		// to prevent returning multiple results for a single nick
		if returnedClients.Has(target) {
			continue
		}
		returnedClients.Add(target)

		var isOper, isAway string

		if target.HasMode(modes.Operator) {
			isOper = "*"
		}
		if target.Away() {
			isAway = "-"
		} else {
			isAway = "+"
		}
		details := target.Details()
		tl.Add(fmt.Sprintf("%s%s=%s%s@%s", details.nick, isOper, isAway, details.username, details.hostname))
	}

	lines := tl.Lines()
	if lines == nil {
		lines = []string{""}
	}
	nick := client.Nick()
	for _, line := range lines {
		rb.Add(nil, client.server.name, RPL_USERHOST, nick, line)
	}

	return false
}

// USERS [parameters]
func usersHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	rb.Add(nil, server.name, ERR_USERSDISABLED, client.Nick(), client.t("USERS has been disabled"))
	return false
}

// VERSION
func versionHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	rb.Add(nil, server.name, RPL_VERSION, client.nick, Ver, server.name)
	server.RplISupport(client, rb)
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
			if info.Certfp != "" && info.Certfp != rb.session.certfp {
				continue
			}

			err, quitMsg := client.ApplyProxiedIP(rb.session, net.ParseIP(msg.Params[3]), secure)
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

const WhoFieldMinimum = int('a') // lowest rune value
const WhoFieldMaximum = int('z')

type WhoFields [WhoFieldMaximum - WhoFieldMinimum + 1]bool

func (fields *WhoFields) Set(field rune) bool {
	index := int(field)
	if WhoFieldMinimum <= index && index <= WhoFieldMaximum {
		fields[int(field)-WhoFieldMinimum] = true
		return true
	} else {
		return false
	}
}
func (fields *WhoFields) Has(field rune) bool {
	return fields[int(field)-WhoFieldMinimum]
}

// rplWhoReply returns the WHO(X) reply between one user and another channel/user.
// who format:
// <channel> <user> <host> <server> <nick> <H|G>[*][~|&|@|%|+][B] :<hopcount> <real name>
// whox format:
// <type> <channel> <user> <ip> <host> <server> <nick> <H|G>[*][~|&|@|%|+][B] <hops> <idle> <account> <rank> :<real name>
func (client *Client) rplWhoReply(channel *Channel, target *Client, rb *ResponseBuffer, isWhox bool, fields WhoFields, whoType string) {
	params := []string{client.Nick()}

	details := target.Details()

	if fields.Has('t') {
		params = append(params, whoType)
	}
	if fields.Has('c') {
		fChannel := "*"
		if channel != nil {
			fChannel = channel.name
		}
		params = append(params, fChannel)
	}
	if fields.Has('u') {
		params = append(params, details.username)
	}
	if fields.Has('i') {
		fIP := "255.255.255.255"
		if client.HasMode(modes.Operator) || client == target {
			// you can only see a target's IP if they're you or you're an oper
			fIP = target.IPString()
		}
		params = append(params, fIP)
	}
	if fields.Has('h') {
		params = append(params, details.hostname)
	}
	if fields.Has('s') {
		params = append(params, target.server.name)
	}
	if fields.Has('n') {
		params = append(params, details.nick)
	}
	if fields.Has('f') { // "flags" (away + oper state + channel status prefix + bot)
		var flags strings.Builder
		if target.Away() {
			flags.WriteRune('G') // Gone
		} else {
			flags.WriteRune('H') // Here
		}

		if target.HasMode(modes.Operator) {
			flags.WriteRune('*')
		}

		if channel != nil {
			flags.WriteString(channel.ClientPrefixes(target, false))
		}

		if target.HasMode(modes.Bot) {
			flags.WriteRune('B')
		}

		params = append(params, flags.String())

	}
	if fields.Has('d') { // server hops from us to target
		params = append(params, "0")
	}
	if fields.Has('l') {
		params = append(params, fmt.Sprintf("%d", target.IdleSeconds()))
	}
	if fields.Has('a') {
		fAccount := "0"
		if details.accountName != "*" {
			// WHOX uses "0" to mean "no account"
			fAccount = details.accountName
		}
		params = append(params, fAccount)
	}
	if fields.Has('o') { // target's channel power level
		//TODO: implement this
		params = append(params, "0")
	}
	if fields.Has('r') {
		params = append(params, details.realname)
	}

	numeric := RPL_WHOSPCRPL
	if !isWhox {
		numeric = RPL_WHOREPLY
		// if this isn't WHOX, stick hops + realname at the end
		params = append(params, "0 "+details.realname)
	}

	rb.Add(nil, client.server.name, numeric, params...)
}

// WHO <mask> [<filter>%<fields>,<type>]
func whoHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	mask := msg.Params[0]
	var err error
	if mask == "" {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.nick, "WHO", client.t("First param must be a mask or channel"))
		return false
	} else if mask[0] == '#' {
		mask, err = CasefoldChannel(msg.Params[0])
	} else {
		mask, err = CanonicalizeMaskWildcard(mask)
	}

	if err != nil {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.Nick(), "WHO", client.t("Mask isn't valid"))
		return false
	}

	sFields := "cuhsnf"
	whoType := "0"
	isWhox := false
	if len(msg.Params) > 1 && strings.Contains(msg.Params[1], "%") {
		isWhox = true
		whoxData := msg.Params[1]
		fieldStart := strings.Index(whoxData, "%")
		sFields = whoxData[fieldStart+1:]

		typeIndex := strings.Index(sFields, ",")
		if typeIndex > -1 && typeIndex < (len(sFields)-1) { // make sure there's , and a value after it
			whoType = sFields[typeIndex+1:]
			sFields = strings.ToLower(sFields[:typeIndex])
		}
	}
	var fields WhoFields
	for _, field := range sFields {
		fields.Set(field)
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
						client.rplWhoReply(channel, member, rb, isWhox, fields, whoType)
					}
				}
			}
		}
	} else {
		// Construct set of channels the client is in.
		userChannels := make(map[*Channel]bool)
		for _, channel := range client.Channels() {
			userChannels[channel] = true
		}

		// Another client is a friend if they share at least one channel, or they are the same client.
		isFriend := func(otherClient *Client) bool {
			if client == otherClient {
				return true
			}

			for _, channel := range otherClient.Channels() {
				if userChannels[channel] {
					return true
				}
			}
			return false
		}

		for mclient := range server.clients.FindAll(mask) {
			if isOper || !mclient.HasMode(modes.Invisible) || isFriend(mclient) {
				client.rplWhoReply(nil, mclient, rb, isWhox, fields, whoType)
			}
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

	handleService := func(nick string) bool {
		cfnick, _ := CasefoldName(nick)
		service, ok := OragonoServices[cfnick]
		if !ok {
			return false
		}
		clientNick := client.Nick()
		rb.Add(nil, client.server.name, RPL_WHOISUSER, clientNick, service.Name, service.Name, "localhost", "*", fmt.Sprintf(client.t("Network service, for more info /msg %s HELP"), service.Name))
		// #1080:
		rb.Add(nil, client.server.name, RPL_WHOISOPERATOR, clientNick, service.Name, client.t("is a network service"))
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
				rb.Add(nil, client.server.name, ERR_NOSUCHNICK, client.Nick(), utils.SafeErrorParam(mask), client.t("No such nick"))
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
			rb.Add(nil, client.server.name, ERR_NOSUCHNICK, client.Nick(), utils.SafeErrorParam(masksString), client.t("No such nick"))
		}
		// fall through, ENDOFWHOIS is always sent
	}
	rb.Add(nil, server.name, RPL_ENDOFWHOIS, client.nick, utils.SafeErrorParam(masksString), client.t("End of /WHOIS list"))
	return false
}

// WHOWAS <nickname> [<count> [<server>]]
func whowasHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	nicknames := strings.Split(msg.Params[0], ",")

	// 0 means "all the entries", as does a negative number
	var count int
	if len(msg.Params) > 1 {
		count, _ = strconv.Atoi(msg.Params[1])
		if count < 0 {
			count = 0
		}
	}
	//var target string
	//if len(msg.Params) > 2 {
	//	target = msg.Params[2]
	//}
	cnick := client.Nick()
	for _, nickname := range nicknames {
		if len(nickname) == 0 {
			continue
		}
		results := server.whoWas.Find(nickname, count)
		if len(results) == 0 {
			rb.Add(nil, server.name, ERR_WASNOSUCHNICK, cnick, utils.SafeErrorParam(nickname), client.t("There was no such nickname"))
		} else {
			for _, whoWas := range results {
				rb.Add(nil, server.name, RPL_WHOWASUSER, cnick, whoWas.nick, whoWas.username, whoWas.hostname, "*", whoWas.realname)
			}
		}
		rb.Add(nil, server.name, RPL_ENDOFWHOWAS, cnick, utils.SafeErrorParam(nickname), client.t("End of WHOWAS"))
	}
	return false
}

// ZNC <module> [params]
func zncHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	zncModuleHandler(client, msg.Params[0], msg.Params[1:], rb)
	return false
}

// fake handler for unknown commands
func unknownCommandHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	rb.Add(nil, server.name, ERR_UNKNOWNCOMMAND, client.Nick(), utils.SafeErrorParam(msg.Command), client.t("Unknown command"))
	return false
}

// fake handler for invalid utf8
func invalidUtf8Handler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	rb.Add(nil, server.name, "FAIL", utils.SafeErrorParam(msg.Command), "INVALID_UTF8", client.t("Message rejected for containing invalid UTF-8"))
	return false
}
