// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2018 Daniel Oaks <daniel@danieloaks.net>
// Copyright (c) 2017-2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"bytes"
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

	"github.com/ergochat/irc-go/ircfmt"
	"github.com/ergochat/irc-go/ircmsg"
	"github.com/ergochat/irc-go/ircutils"
	"golang.org/x/crypto/bcrypt"

	"github.com/ergochat/ergo/irc/caps"
	"github.com/ergochat/ergo/irc/custime"
	"github.com/ergochat/ergo/irc/flatip"
	"github.com/ergochat/ergo/irc/history"
	"github.com/ergochat/ergo/irc/jwt"
	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/oauth2"
	"github.com/ergochat/ergo/irc/sno"
	"github.com/ergochat/ergo/irc/utils"
	"github.com/ergochat/ergo/irc/webpush"
)

// helper function to parse ACC callbacks, e.g., mailto:person@example.com, tel:16505551234
func parseCallback(spec string, config *Config) (callbackNamespace string, callbackValue string, err error) {
	// XXX if we don't require verification, ignore any callback that was passed here
	// (to avoid confusion in the case where the ircd has no mail server configured)
	if !config.Accounts.Registration.EmailVerification.Enabled {
		callbackNamespace = "*"
		return
	}
	callback := strings.ToLower(spec)
	if colonIndex := strings.IndexByte(callback, ':'); colonIndex != -1 {
		callbackNamespace, callbackValue = callback[:colonIndex], callback[colonIndex+1:]
	} else {
		// "If a callback namespace is not ... provided, the IRC server MUST use mailto""
		callbackNamespace = "mailto"
		callbackValue = callback
	}

	if config.Accounts.Registration.EmailVerification.Enabled {
		if callbackNamespace != "mailto" {
			err = errValidEmailRequired
		} else if strings.IndexByte(callbackValue, '@') < 1 {
			err = errValidEmailRequired
		}
	}

	return
}

func registrationErrorToMessage(config *Config, client *Client, err error) (message string) {
	if emailError := registrationCallbackErrorText(config, client, err); emailError != "" {
		return emailError
	}

	switch err {
	case errAccountAlreadyRegistered, errAccountAlreadyVerified, errAccountAlreadyUnregistered, errAccountAlreadyLoggedIn, errAccountCreation, errAccountMustHoldNick, errAccountBadPassphrase, errCertfpAlreadyExists, errFeatureDisabled, errAccountBadPassphrase, errNameReserved:
		message = err.Error()
	case errLimitExceeded:
		message = `There have been too many registration attempts recently; try again later`
	default:
		// default response: let's be risk-averse about displaying internal errors
		// to the clients, especially for something as sensitive as accounts
		message = `Could not register`
	}
	return
}

func announcePendingReg(client *Client, rb *ResponseBuffer, accountName string) {
	client.server.snomasks.Send(sno.LocalAccounts, fmt.Sprintf(ircfmt.Unescape("Client $c[grey][$r%s$c[grey]] attempted to register account $c[grey][$r%s$c[grey]] from IP %s, pending verification"), client.Nick(), accountName, rb.session.IP().String()))
}

// helper function to dispatch messages when a client successfully registers
func sendSuccessfulRegResponse(service *ircService, client *Client, rb *ResponseBuffer) {
	details := client.Details()
	if service != nil {
		service.Notice(rb, client.t("Account created"))
	}
	client.server.snomasks.Send(sno.LocalAccounts, fmt.Sprintf(ircfmt.Unescape("Client $c[grey][$r%s$c[grey]] registered account $c[grey][$r%s$c[grey]] from IP %s"), details.nickMask, details.accountName, rb.session.IP().String()))
	sendSuccessfulAccountAuth(service, client, rb, false)
}

// sendSuccessfulAccountAuth means that an account auth attempt completed successfully, and is used to dispatch messages.
func sendSuccessfulAccountAuth(service *ircService, client *Client, rb *ResponseBuffer, forSASL bool) {
	details := client.Details()

	if service != nil {
		service.Notice(rb, fmt.Sprintf(client.t("You're now logged in as %s"), details.accountName))
	} else {
		//TODO(dan): some servers send this numeric even for NickServ logins iirc? to confirm and maybe do too
		rb.Add(nil, client.server.name, RPL_LOGGEDIN, details.nick, details.nickMask, details.accountName, fmt.Sprintf(client.t("You are now logged in as %s"), details.accountName))
		if forSASL {
			rb.Add(nil, client.server.name, RPL_SASLSUCCESS, details.nick, client.t("Authentication successful"))
		}
	}

	if client.Registered() {
		// dispatch account-notify
		for friend := range client.FriendsMonitors(caps.AccountNotify) {
			if friend != rb.session {
				friend.Send(nil, details.nickMask, "ACCOUNT", details.accountName)
			}
		}
		if rb.session.capabilities.Has(caps.AccountNotify) {
			rb.Add(nil, details.nickMask, "ACCOUNT", details.accountName)
		}
		client.server.sendLoginSnomask(details.nickMask, details.accountName)
	}

	// #1479: for Tor clients, replace the hostname with the always-on cloak here
	// (for normal clients, this would discard the IP-based cloak, but with Tor
	// there's no such concern)
	if rb.session.isTor {
		config := client.server.Config()
		if config.Server.Cloaks.EnabledForAlwaysOn {
			cloakedHostname := config.Server.Cloaks.ComputeAccountCloak(details.accountName)
			client.setCloakedHostname(cloakedHostname)
			if client.registered {
				client.sendChghost(details.nickMask, client.Hostname())
			}
		}
	}

	client.server.logger.Info("accounts", "client", details.nick, "logged into account", details.accountName)
}

func (server *Server) sendLoginSnomask(nickMask, accountName string) {
	server.snomasks.Send(sno.LocalAccounts, fmt.Sprintf(ircfmt.Unescape("Client $c[grey][$r%s$c[grey]] logged into account $c[grey][$r%s$c[grey]]"), nickMask, accountName))
}

// ACCEPT <nicklist>
// nicklist is a comma-delimited list of nicknames; each may be prefixed with -
// to indicate that it should be removed from the list
func acceptHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	for _, tNick := range strings.Split(msg.Params[0], ",") {
		add := true
		if strings.HasPrefix(tNick, "-") {
			add = false
			tNick = strings.TrimPrefix(tNick, "-")
		}

		target := server.clients.Get(tNick)
		if target == nil {
			rb.Add(nil, server.name, "FAIL", "ACCEPT", "INVALID_USER", utils.SafeErrorParam(tNick), client.t("No such user"))
			continue
		}

		if add {
			server.accepts.Accept(client, target)
		} else {
			server.accepts.Unaccept(client, target)
		}

		// https://github.com/solanum-ircd/solanum/blob/main/doc/features/modeg.txt
		// Charybdis/Solanum define various error numerics that could be sent here,
		// but this doesn't seem important to me. One thing to note is that we are not
		// imposing an upper bound on the size of the accept list, since in our
		// implementation you can only ACCEPT clients who are actually present,
		// and an attacker attempting to DoS has much easier resource exhaustion
		// strategies available (for example, channel history buffers).
	}

	return false
}

const (
	saslMaxResponseLength = 8192 // implementation-defined sanity check, long enough for bearer tokens
)

// AUTHENTICATE [<mechanism>|<data>|*]
func authenticateHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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

	// start new sasl session: parameter is the authentication mechanism
	if session.sasl.mechanism == "" {
		mechanism := strings.ToUpper(msg.Params[0])
		_, mechanismIsEnabled := EnabledSaslMechanisms[mechanism]

		// The spec says: "The AUTHENTICATE command MUST be used before registration
		// is complete and with the sasl capability enabled." Enforcing this universally
		// would simplify the implementation somewhat, but we've never enforced it before
		// and I don't want to break working clients that use PLAIN or EXTERNAL
		// and violate this MUST (e.g. by sending CAP END too early).
		if client.registered && !(mechanism == "PLAIN" || mechanism == "EXTERNAL") {
			rb.Add(nil, server.name, ERR_SASLFAIL, details.nick, client.t("SASL is only allowed before connection registration"))
			return false
		}

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

	// continue existing sasl session: parameter is a message chunk
	done, value, err := session.sasl.value.Add(msg.Params[0])
	if err == nil {
		if done {
			// call actual handler
			handler := EnabledSaslMechanisms[session.sasl.mechanism]
			return handler(server, client, session, value, rb)
		} else {
			return false // wait for continuation line
		}
	}
	// else: error handling
	switch err {
	case ircutils.ErrSASLTooLong:
		rb.Add(nil, server.name, ERR_SASLTOOLONG, details.nick, client.t("SASL message too long"))
	case ircutils.ErrSASLLimitExceeded:
		rb.Add(nil, server.name, ERR_SASLFAIL, details.nick, client.t("SASL authentication failed: Passphrase too long"))
	default:
		rb.Add(nil, server.name, ERR_SASLFAIL, details.nick, client.t("SASL authentication failed: Invalid b64 encoding"))
	}
	session.sasl.Clear()
	return false
}

// AUTHENTICATE PLAIN
func authPlainHandler(server *Server, client *Client, session *Session, value []byte, rb *ResponseBuffer) bool {
	defer session.sasl.Clear()

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
		sendAuthErrorResponse(client, rb, err)
		return false
	} else if !fixupNickEqualsAccount(client, rb, server.Config(), "") {
		return false
	}

	sendSuccessfulAccountAuth(nil, client, rb, true)
	return false
}

// AUTHENTICATE IRCV3BEARER
func authIRCv3BearerHandler(server *Server, client *Client, session *Session, value []byte, rb *ResponseBuffer) bool {
	defer session.sasl.Clear()

	// <authzid> \x00 <type> \x00 <token>
	splitValue := bytes.SplitN(value, []byte{'\000'}, 3)
	if len(splitValue) != 3 {
		rb.Add(nil, server.name, ERR_SASLFAIL, client.Nick(), client.t("SASL authentication failed: Invalid auth blob"))
		return false
	}

	err := server.accounts.AuthenticateByBearerToken(client, string(splitValue[1]), string(splitValue[2]))
	if err != nil {
		sendAuthErrorResponse(client, rb, err)
		return false
	}

	sendSuccessfulAccountAuth(nil, client, rb, true)
	return false
}

func sendAuthErrorResponse(client *Client, rb *ResponseBuffer, err error) {
	msg := authErrorToMessage(client.server, err)
	rb.Add(nil, client.server.name, ERR_SASLFAIL, client.nick, fmt.Sprintf("%s: %s", client.t("SASL authentication failed"), client.t(msg)))
	if err == errAccountUnverified {
		rb.Add(nil, client.server.name, "NOTE", "AUTHENTICATE", "VERIFICATION_REQUIRED", "*", client.t(err.Error()))
	}
}

func authErrorToMessage(server *Server, err error) (msg string) {
	if throttled, ok := err.(*ThrottleError); ok {
		return throttled.Error()
	}

	switch err {
	case errAccountDoesNotExist, errAccountUnverified, errAccountInvalidCredentials, errAuthzidAuthcidMismatch, errNickAccountMismatch, errAccountSuspended, oauth2.ErrInvalidToken:
		return err.Error()
	default:
		// don't expose arbitrary error messages to the user
		server.logger.Error("internal", "sasl authentication failure", err.Error())
		return "Unknown"
	}
}

// AUTHENTICATE EXTERNAL
func authExternalHandler(server *Server, client *Client, session *Session, value []byte, rb *ResponseBuffer) bool {
	defer session.sasl.Clear()

	if rb.session.certfp == "" {
		rb.Add(nil, server.name, ERR_SASLFAIL, client.nick, client.t("SASL authentication failed, you are not connecting with a certificate"))
		return false
	}

	// EXTERNAL doesn't carry an authentication ID (this is determined from the
	// certificate), but does carry an optional authorization ID.
	authzid := string(value)
	var deviceID string
	var err error
	// see #843: strip the device ID for the benefit of clients that don't
	// distinguish user/ident from account name
	if strudelIndex := strings.IndexByte(authzid, '@'); strudelIndex != -1 {
		authzid, deviceID = authzid[:strudelIndex], authzid[strudelIndex+1:]
	}

	if err == nil {
		err = server.accounts.AuthenticateByCertificate(client, rb.session.certfp, rb.session.peerCerts, authzid)
	}
	if err != nil {
		sendAuthErrorResponse(client, rb, err)
		return false
	} else if !fixupNickEqualsAccount(client, rb, server.Config(), "") {
		return false
	}

	sendSuccessfulAccountAuth(nil, client, rb, true)
	if !client.registered && deviceID != "" {
		rb.session.deviceID = deviceID
	}
	return false
}

// AUTHENTICATE SCRAM-SHA-256
func authScramHandler(server *Server, client *Client, session *Session, value []byte, rb *ResponseBuffer) bool {
	continueAuth := true
	defer func() {
		if !continueAuth {
			session.sasl.Clear()
		}
	}()

	// first message? if so, initialize the SCRAM conversation
	if session.sasl.scramConv == nil {
		if throttled, remainingTime := client.checkLoginThrottle(); throttled {
			rb.Add(nil, server.name, ERR_SASLFAIL, client.Nick(),
				fmt.Sprintf(client.t("Please wait at least %v and try again"), remainingTime.Round(time.Millisecond)))
			continueAuth = false
			return false
		}
		session.sasl.scramConv = server.accounts.NewScramConversation()
	}

	// wait for a final AUTHENTICATE + from the client to conclude authentication
	if session.sasl.scramConv.Done() {
		continueAuth = false
		if session.sasl.scramConv.Valid() {
			authcid := session.sasl.scramConv.Username()
			if strudelIndex := strings.IndexByte(authcid, '@'); strudelIndex != -1 {
				var deviceID string
				authcid, deviceID = authcid[:strudelIndex], authcid[strudelIndex+1:]
				if !client.registered {
					rb.session.deviceID = deviceID
				}
			}
			authzid := session.sasl.scramConv.AuthzID()
			if authzid != "" && authzid != authcid {
				rb.Add(nil, server.name, ERR_SASLFAIL, client.nick, client.t("SASL authentication failed: authcid and authzid should be the same"))
				return false
			}
			account, err := server.accounts.LoadAccount(authcid)
			if err == nil {
				server.accounts.Login(client, account)
				// fixupNickEqualsAccount is not needed for unregistered clients
				sendSuccessfulAccountAuth(nil, client, rb, true)
			} else {
				server.logger.Error("internal", "SCRAM succeeded but couldn't load account", authcid, err.Error())
				rb.Add(nil, server.name, ERR_SASLFAIL, client.nick, client.t("SASL authentication failed"))
			}
		} else {
			rb.Add(nil, server.name, ERR_SASLFAIL, client.nick, client.t("SASL authentication failed"))
		}
		return false
	}

	response, err := session.sasl.scramConv.Step(string(value))
	if err == nil {
		sendSASLChallenge(server, rb, []byte(response))
	} else {
		continueAuth = false
		rb.Add(nil, server.name, ERR_SASLFAIL, client.Nick(), err.Error())
		return false
	}

	return false
}

// AUTHENTICATE OAUTHBEARER
func authOauthBearerHandler(server *Server, client *Client, session *Session, value []byte, rb *ResponseBuffer) bool {
	if !server.Config().Accounts.OAuth2.Enabled {
		rb.Add(nil, server.name, ERR_SASLFAIL, client.Nick(), "SASL authentication failed: mechanism not enabled")
		return false
	}

	if session.sasl.oauthConv == nil {
		session.sasl.oauthConv = oauth2.NewOAuthBearerServer(
			func(opts oauth2.OAuthBearerOptions) *oauth2.OAuthBearerError {
				err := server.accounts.AuthenticateByOAuthBearer(client, opts)
				switch err {
				case nil:
					return nil
				case oauth2.ErrInvalidToken:
					return &oauth2.OAuthBearerError{Status: "invalid_token", Schemes: "bearer"}
				case errFeatureDisabled:
					return &oauth2.OAuthBearerError{Status: "invalid_request", Schemes: "bearer"}
				default:
					// this is probably a misconfiguration or infrastructure error so we should log it
					server.logger.Error("internal", "failed to validate OAUTHBEARER token", err.Error())
					// tell the client it was their fault even though it probably wasn't:
					return &oauth2.OAuthBearerError{Status: "invalid_request", Schemes: "bearer"}
				}
			},
		)
	}

	challenge, done, err := session.sasl.oauthConv.Next(value)
	if done {
		if err == nil {
			sendSuccessfulAccountAuth(nil, client, rb, true)
		} else {
			rb.Add(nil, server.name, ERR_SASLFAIL, client.Nick(), ircutils.SanitizeText(err.Error(), 350))
		}
		session.sasl.Clear()
	} else {
		// ignore `err`, we need to relay the challenge (which may contain a JSON-encoded error)
		// to the client
		sendSASLChallenge(server, rb, challenge)
	}
	return false
}

// helper to b64 a sasl response and chunk it into 400-byte lines
// as per https://ircv3.net/specs/extensions/sasl-3.1
func sendSASLChallenge(server *Server, rb *ResponseBuffer, challenge []byte) {
	for _, chunk := range ircutils.EncodeSASLResponse(challenge) {
		rb.Add(nil, server.name, "AUTHENTICATE", chunk)
	}
}

// AWAY [<message>]
func awayHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	// #1996: `AWAY :` is treated the same as `AWAY`
	var awayMessage string
	if len(msg.Params) > 0 {
		awayMessage = msg.Params[0]
		awayMessage = ircmsg.TruncateUTF8Safe(awayMessage, server.Config().Limits.AwayLen)
	}

	wasAway, nowAway := rb.session.SetAway(awayMessage)

	if nowAway != "" {
		rb.Add(nil, server.name, RPL_NOWAWAY, client.nick, client.t("You have been marked as being away"))
	} else {
		rb.Add(nil, server.name, RPL_UNAWAY, client.nick, client.t("You are no longer marked as being away"))
	}

	if client.registered && wasAway != nowAway {
		dispatchAwayNotify(client, nowAway)
	} // else: we'll send it (if applicable) after reattach

	return false
}

func dispatchAwayNotify(client *Client, awayMessage string) {
	// dispatch away-notify
	details := client.Details()
	isBot := client.HasMode(modes.Bot)
	for session := range client.FriendsMonitors(caps.AwayNotify) {
		if awayMessage != "" {
			session.sendFromClientInternal(false, time.Time{}, "", details.nickMask, details.accountName, isBot, nil, "AWAY", awayMessage)
		} else {
			session.sendFromClientInternal(false, time.Time{}, "", details.nickMask, details.accountName, isBot, nil, "AWAY")
		}
	}
}

// BATCH {+,-}reference-tag type [params...]
func batchHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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

// CAP <subcmd> [<caps>]
func capHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	details := client.Details()
	subCommand := strings.ToUpper(msg.Params[0])
	toAdd := caps.NewSet()
	toRemove := caps.NewSet()
	var capString string

	config := server.Config()
	supportedCaps := config.Server.supportedCaps
	if client.isSTSOnly {
		supportedCaps = stsOnlyCaps
	} else if rb.session.hideSTS {
		supportedCaps = config.Server.supportedCapsWithoutSTS
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
		// 1. WeeChat 1.4 won't accept the CAP reply unless it contains the server.name source
		// 2. old versions of Kiwi and The Lounge can't parse multiline CAP LS 302 (#661),
		// so try as hard as possible to get the response to fit on one line.
		// :server.name CAP nickname LS * :<tokens>\r\n
		// 1           [5  ]        1  [4 ]        [2 ]
		maxLen := (MaxLineLen - 2) - 1 - len(server.name) - 5 - len(details.nick) - 1 - len(subCommand) - 4
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
func chathistoryHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) (exiting bool) {
	var items []history.Item
	var target string
	var channel *Channel
	var sequence history.Sequence
	var err error
	var listTargets bool
	var targets []history.TargetListing
	defer func() {
		// errors are sent either without a batch, or in a draft/labeled-response batch as usual
		if err == utils.ErrInvalidParams {
			rb.Add(nil, server.name, "FAIL", "CHATHISTORY", "INVALID_PARAMS", msg.Params[0], client.t("Invalid parameters"))
		} else if !listTargets && sequence == nil {
			rb.Add(nil, server.name, "FAIL", "CHATHISTORY", "INVALID_TARGET", msg.Params[0], utils.SafeErrorParam(target), client.t("Messages could not be retrieved"))
		} else if err != nil {
			rb.Add(nil, server.name, "FAIL", "CHATHISTORY", "MESSAGE_ERROR", msg.Params[0], client.t("Messages could not be retrieved"))
		} else {
			// successful responses are sent as a chathistory or history batch
			if listTargets {
				batchID := rb.StartNestedBatch(caps.ChathistoryTargetsBatchType)
				defer rb.EndNestedBatch(batchID)
				for _, target := range targets {
					name := server.UnfoldName(target.CfName)
					rb.Add(nil, server.name, "CHATHISTORY", "TARGETS", name,
						target.Time.Format(IRCv3TimestampFormat))
				}
			} else if channel != nil {
				channel.replayHistoryItems(rb, items, true)
			} else {
				client.replayPrivmsgHistory(rb, items, target, true)
			}
		}
	}()

	config := server.Config()
	maxChathistoryLimit := config.History.ChathistoryMax
	if maxChathistoryLimit == 0 {
		return
	}
	preposition := strings.ToLower(msg.Params[0])
	target = msg.Params[1]
	listTargets = (preposition == "targets")

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
			msgid, err = history.NormalizeMsgid(value), nil
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

	roundUp := func(endpoint time.Time) (result time.Time) {
		return endpoint.Truncate(time.Millisecond).Add(time.Millisecond)
	}

	paramPos := 2
	var start, end history.Selector
	var limit int
	switch preposition {
	case "targets":
		// use the same selector parsing as BETWEEN,
		// except that we have no target so we have one fewer parameter
		paramPos = 1
		fallthrough
	case "between":
		start.Msgid, start.Time, err = parseQueryParam(msg.Params[paramPos])
		if err != nil {
			return
		}
		end.Msgid, end.Time, err = parseQueryParam(msg.Params[paramPos+1])
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
		limit = parseHistoryLimit(paramPos + 2)
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
		err = utils.ErrInvalidParams
		return
	}

	if listTargets {
		targets, err = client.listTargets(start, end, limit)
	} else {
		channel, sequence, err = server.GetHistorySequence(nil, client, target)
		if err != nil || sequence == nil {
			return
		}
		if preposition == "around" {
			items, err = sequence.Around(start, limit)
		} else {
			items, err = sequence.Between(start, end, limit)
		}
	}
	return
}

// DEBUG <subcmd>
func debugHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	param := strings.ToUpper(msg.Params[0])

	switch param {
	case "GCSTATS":
		stats := debug.GCStats{
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
		profFile := server.Config().getOutputPath("ergo.mprof")
		file, err := os.Create(profFile)
		if err != nil {
			rb.Notice(fmt.Sprintf("error: %s", err))
			break
		}
		defer file.Close()
		pprof.Lookup("heap").WriteTo(file, 0)
		rb.Notice(fmt.Sprintf("written to %s", profFile))

	case "STARTCPUPROFILE":
		profFile := server.Config().getOutputPath("ergo.prof")
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

func defconHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	if len(msg.Params) > 0 {
		level, err := strconv.Atoi(msg.Params[0])
		if err == nil && 1 <= level && level <= 5 {
			server.SetDefcon(uint32(level))
			server.snomasks.Send(sno.LocalAnnouncements, fmt.Sprintf("%s [%s] set DEFCON level to %d", client.Nick(), client.Oper().Name, level))
		} else {
			rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.Nick(), msg.Command, client.t("Invalid DEFCON parameter"))
			return false
		}
	}
	rb.Notice(fmt.Sprintf(client.t("Current DEFCON level is %d"), server.Defcon()))
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
	desc = fmt.Sprintf("%s [%s] added on [%s]", desc, info.TimeLeft(), info.TimeCreated.UTC().Format(time.RFC1123))
	banType := "Ban"
	if info.RequireSASL {
		banType = "SASL required"
	}
	return fmt.Sprintf(client.t("%[1]s - %[2]s - added by %[3]s - %[4]s"), banType, key, info.OperName, desc)
}

// DLINE [ANDKILL] [MYSELF] [duration] <ip>/<net> [ON <server>] [reason [| oper reason]]
// DLINE LIST
func dlineHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	// check oper permissions
	oper := client.Oper()
	if !oper.HasRoleCapab("ban") {
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

	if !dlineMyself && hostNet.Contains(rb.session.IP()) {
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

	err = server.dlines.AddNetwork(flatip.FromNetIPNet(hostNet), duration, false, reason, operReason, operName)

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
		var sessionsToKill []*Session
		var killedClientNicks []string

		for _, mcl := range server.clients.AllClients() {
			nickKilled := false
			for _, session := range mcl.Sessions() {
				if hostNet.Contains(session.IP()) {
					sessionsToKill = append(sessionsToKill, session)
					if !nickKilled {
						killedClientNicks = append(killedClientNicks, mcl.Nick())
						nickKilled = true
					}
				}
			}
		}

		for _, session := range sessionsToKill {
			mcl := session.client
			mcl.Quit(fmt.Sprintf(mcl.t("You have been banned from this server (%s)"), reason), session)
			if session == rb.session {
				killClient = true
			} else {
				// if mcl == client, we kill them below
				mcl.destroy(session)
			}
		}

		// send snomask
		sort.Strings(killedClientNicks)
		server.snomasks.Send(sno.LocalKills, fmt.Sprintf(ircfmt.Unescape("%s [%s] killed %d clients with a DLINE $c[grey][$r%s$c[grey]]"), client.nick, operName, len(killedClientNicks), strings.Join(killedClientNicks, ", ")))
	}

	return killClient
}

// EXTJWT <target> [service_name]
func extjwtHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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
		if present, joinTimeSecs, cModes := channel.ClientStatus(client); present {
			claims["joined"] = joinTimeSecs
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
		maxTokenLength := maxLastArgLength

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
// HELPOP [<query>]
func helpHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	if len(msg.Params) == 0 {
		client.sendHelp("HELPOP", client.t(`HELPOP <argument>

Get an explanation of <argument>, or "index" for a list of help topics.`), rb)
		return false
	}

	argument := strings.ToLower(strings.TrimSpace(msg.Params[0]))

	// handle index
	if argument == "index" {
		client.sendHelp("HELP", server.helpIndexManager.GetIndex(client.Languages(), client.HasMode(modes.Operator)), rb)
		return false
	}

	helpHandler, exists := Help[argument]

	if exists && (!helpHandler.oper || (helpHandler.oper && client.HasMode(modes.Operator))) {
		if helpHandler.textGenerator != nil {
			client.sendHelp(argument, helpHandler.textGenerator(client), rb)
		} else {
			client.sendHelp(argument, client.t(helpHandler.text), rb)
		}
	} else {
		rb.Add(nil, server.name, ERR_HELPNOTFOUND, client.Nick(), strings.ToUpper(utils.SafeErrorParam(argument)), client.t("Help not found"))
	}

	return false
}

// HISTORY <target> [<limit>]
// e.g., HISTORY #ubuntu 10
// HISTORY alice 15
// HISTORY #darwin 1h
func historyHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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
			channel.replayHistoryItems(rb, items, true)
		} else {
			client.replayPrivmsgHistory(rb, items, "", true)
		}
	}
	return false
}

// INFO
func infoHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	nick := client.Nick()
	// we do the below so that the human-readable lines in info can be translated.
	for _, line := range infoString1 {
		rb.Add(nil, server.name, RPL_INFO, nick, line)
	}
	rb.Add(nil, server.name, RPL_INFO, nick, fmt.Sprintf(client.t("This is Ergo version %s."), SemVer))
	if Commit != "" {
		rb.Add(nil, server.name, RPL_INFO, nick, fmt.Sprintf(client.t("It was built from git hash %s."), Commit))
	}
	rb.Add(nil, server.name, RPL_INFO, nick, fmt.Sprintf(client.t("It was compiled using %s."), runtime.Version()))
	rb.Add(nil, server.name, RPL_INFO, nick, fmt.Sprintf(client.t("This server has been running since %s."), server.ctime.Format(time.RFC1123)))
	rb.Add(nil, server.name, RPL_INFO, nick, "")
	rb.Add(nil, server.name, RPL_INFO, nick, client.t("Ergo is released under the MIT license."))
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
	rb.Add(nil, server.name, RPL_INFO, nick, "    https://github.com/ergochat/ergo/blob/master/CHANGELOG.md")
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
// UNINVITE <nickname> <channel>
func inviteHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	invite := msg.Command == "INVITE"
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

	if invite {
		channel.Invite(target, client, rb)
	} else {
		channel.Uninvite(target, client, rb)
	}

	return false
}

// ISON <nick>{ <nick>}
func isonHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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

// ISUPPORT
func isupportHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	server.RplISupport(client, rb)
	if !client.registered {
		rb.session.isupportSentPrereg = true
	}
	return false
}

// JOIN <channel>{,<channel>} [<key>{,<key>}]
func joinHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	// #1417: allow `JOIN 0` with a confirmation code
	if msg.Params[0] == "0" {
		expectedCode := utils.ConfirmationCode("", rb.session.ctime)
		if len(msg.Params) == 1 || msg.Params[1] != expectedCode {
			rb.Notice(fmt.Sprintf(client.t("Warning: /JOIN 0 will remove you from all channels. To confirm, type: /JOIN 0 %s"), expectedCode))
		} else {
			for _, channel := range client.Channels() {
				channel.Part(client, "", rb)
			}
		}
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
		err, forward := server.channels.Join(client, name, key, false, rb)
		if err != nil {
			if forward != "" {
				rb.Add(nil, server.name, ERR_LINKCHANNEL, client.Nick(), utils.SafeErrorParam(name), forward, client.t("Forwarding to another channel"))
				name = forward
				err, _ = server.channels.Join(client, name, key, false, rb)
			}
			if err != nil {
				sendJoinError(client, name, rb, err)
			}
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
func sajoinHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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

	message := fmt.Sprintf("Operator %s ran SAJOIN %s", client.Oper().Name, strings.Join(msg.Params, " "))
	server.snomasks.Send(sno.LocalOpers, message)
	server.logger.Info("opers", message)

	channels := strings.Split(channelString, ",")
	for _, chname := range channels {
		err, _ := server.channels.Join(target, chname, "", true, rb)
		if err != nil {
			sendJoinError(client, chname, rb, err)
		}
	}
	return false
}

// KICK <channel>{,<channel>} <user>{,<user>} [<comment>]
// RFC 2812 requires the number of channels to be either 1 or equal to
// the number of users.
// Addditionally, we support multiple channels and a single user.
func kickHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	channels := strings.Split(msg.Params[0], ",")
	users := strings.Split(msg.Params[1], ",")
	if (len(channels) != len(users)) && (len(users) != 1) && (len(channels) != 1) {
		rb.Add(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, "KICK", client.t("Not enough parameters"))
		return false
	}

	type kickCmd struct {
		channel string
		nick    string
	}
	var kicks []kickCmd
	if len(users) == 1 {
		kicks = make([]kickCmd, 0, len(channels))
		// Single user, possibly multiple channels
		user := users[0]
		for _, channel := range channels {
			if channel == "" {
				continue // #679
			}
			kicks = append(kicks, kickCmd{channel, user})
		}
	} else {
		// Multiple users, either a single channel or as many channels
		// as users.
		kicks = make([]kickCmd, 0, len(users))
		channel := channels[0]
		for index, user := range users {
			if len(channels) > 1 {
				channel = channels[index]
			}
			if channel == "" {
				continue // #679
			}
			kicks = append(kicks, kickCmd{channel, user})
		}
	}

	var comment string
	if len(msg.Params) > 2 {
		comment = msg.Params[2]
	}
	if comment == "" {
		comment = client.Nick()
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
		channel.Kick(client, target, comment, rb, false)
	}
	return false
}

// KILL <nickname> <comment>
func killHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	nickname := msg.Params[0]
	var comment string
	if len(msg.Params) > 1 {
		comment = msg.Params[1]
	}

	target := server.clients.Get(nickname)
	if target == nil {
		rb.Add(nil, client.server.name, ERR_NOSUCHNICK, client.Nick(), utils.SafeErrorParam(nickname), client.t("No such nick"))
		return false
	} else if target.AlwaysOn() {
		rb.Add(nil, client.server.name, ERR_UNKNOWNERROR, client.Nick(), "KILL", fmt.Sprintf(client.t("Client %s is always-on and cannot be fully removed by /KILL; consider /UBAN ADD instead"), target.Nick()))
	}

	quitMsg := "Killed"
	if comment != "" {
		quitMsg = fmt.Sprintf("Killed by %s: %s", client.Nick(), comment)
	}

	var snoLine string
	if comment == "" {
		snoLine = fmt.Sprintf(ircfmt.Unescape("%s was killed by %s"), target.Nick(), client.Nick())
	} else {
		snoLine = fmt.Sprintf(ircfmt.Unescape("%s was killed by %s $c[grey][$r%s$c[grey]]"), target.Nick(), client.Nick(), comment)
	}
	server.snomasks.Send(sno.LocalKills, snoLine)

	target.Quit(quitMsg, nil)
	target.destroy(nil)
	return false
}

// KLINE [ANDKILL] [MYSELF] [duration] <mask> [ON <server>] [reason [| oper reason]]
// KLINE LIST
func klineHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	details := client.Details()
	// check oper permissions
	oper := client.Oper()
	if !oper.HasRoleCapab("ban") {
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
					break
				}
			}
		}

		for _, mcl := range clientsToKill {
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
func languageHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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
func listHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	config := server.Config()
	if time.Since(client.ctime) < config.Channels.ListDelay && client.Account() == "" && !client.HasMode(modes.Operator) {
		remaining := time.Until(client.ctime.Add(config.Channels.ListDelay))
		rb.Notice(fmt.Sprintf(client.t("This server requires that you wait %v after connecting before you can use /LIST. You have %v left."), config.Channels.ListDelay, remaining.Round(time.Millisecond)))
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
		members, name, topic := channel.listData()
		rb.Add(nil, client.server.name, RPL_LIST, nick, name, strconv.Itoa(members), topic)
	}

	clientIsOp := client.HasRoleCapabs("sajoin")
	if len(channels) == 0 {
		for _, channel := range server.channels.ListableChannels() {
			if !clientIsOp && channel.flags.HasMode(modes.Secret) && !channel.hasClient(client) {
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
			if channel == nil || (!clientIsOp && channel.flags.HasMode(modes.Secret) && !channel.hasClient(client)) {
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
func lusersHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	server.Lusers(client, rb)
	return false
}

// MODE <target> [<modestring> [<mode arguments>...]]
func modeHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	if 0 < len(msg.Params[0]) && msg.Params[0][0] == '#' {
		return cmodeHandler(server, client, msg, rb)
	}
	return umodeHandler(server, client, msg, rb)
}

// MODE <channel> [<modestring> [<mode arguments>...]]
func cmodeHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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

	isSamode := msg.Command == "SAMODE"
	if isSamode {
		message := fmt.Sprintf("Operator %s ran SAMODE %s", client.Oper().Name, strings.Join(msg.Params, " "))
		server.snomasks.Send(sno.LocalOpers, message)
		server.logger.Info("opers", message)
	}

	// process mode changes, include list operations (an empty set of changes does a list)
	applied := channel.ApplyChannelModeChanges(client, isSamode, changes, rb)
	details := client.Details()
	isBot := client.HasMode(modes.Bot)
	announceCmodeChanges(channel, applied, details.nickMask, details.accountName, details.account, isBot, rb)

	return false
}

func announceCmodeChanges(channel *Channel, applied modes.ModeChanges, source, accountName, account string, isBot bool, rb *ResponseBuffer) {
	// send out changes
	if len(applied) > 0 {
		message := utils.MakeMessage("")
		changeStrings := applied.Strings()
		for _, changeString := range changeStrings {
			message.Split = append(message.Split, utils.MessagePair{Message: changeString})
		}
		args := append([]string{channel.name}, changeStrings...)
		rb.AddFromClient(message.Time, message.Msgid, source, accountName, isBot, nil, "MODE", args...)
		for _, member := range channel.Members() {
			for _, session := range member.Sessions() {
				if session != rb.session {
					session.sendFromClientInternal(false, message.Time, message.Msgid, source, accountName, isBot, nil, "MODE", args...)
				}
			}
		}
		channel.AddHistoryItem(history.Item{
			Type:        history.Mode,
			Nick:        source,
			AccountName: accountName,
			Message:     message,
			IsBot:       isBot,
		}, account)
	}
}

// MODE <client> [<modestring> [<mode arguments>...]]
func umodeHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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

	if msg.Command == "SAMODE" {
		message := fmt.Sprintf("Operator %s ran SAMODE %s", client.Oper().Name, strings.Join(msg.Params, " "))
		server.snomasks.Send(sno.LocalOpers, message)
		server.logger.Info("opers", message)
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
		if target.HasMode(modes.Operator) {
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
	if service, isService := ErgoServices[strings.ToLower(nick)]; isService {
		return service.Name
	} else if iclient := server.clients.Get(nick); iclient != nil {
		return iclient.Nick()
	}
	return ""
}

// MONITOR <subcmd> [params...]
func monitorHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	handler, exists := monitorSubcommands[strings.ToLower(msg.Params[0])]

	if !exists {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.Nick(), "MONITOR", msg.Params[0], client.t("Unknown subcommand"))
		return false
	}

	return handler(server, client, msg, rb)
}

// MONITOR - <target>{,<target>}
func monitorRemoveHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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
func monitorAddHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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
func monitorClearHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	server.monitorManager.RemoveAll(rb.session)
	return false
}

// MONITOR L
func monitorListHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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

	for _, line := range utils.BuildTokenLines(maxLastArgLength, nickList, ",") {
		rb.Add(nil, server.name, RPL_MONLIST, nick, line)
	}

	rb.Add(nil, server.name, RPL_ENDOFMONLIST, nick, "End of MONITOR list")

	return false
}

// MONITOR S
func monitorStatusHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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
		for _, line := range utils.BuildTokenLines(maxLastArgLength, online, ",") {
			rb.Add(nil, server.name, RPL_MONONLINE, client.Nick(), line)
		}
	}
	if len(offline) > 0 {
		for _, line := range utils.BuildTokenLines(maxLastArgLength, offline, ",") {
			rb.Add(nil, server.name, RPL_MONOFFLINE, client.Nick(), line)
		}
	}

	return false
}

// MOTD
func motdHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	server.MOTD(client, rb)
	return false
}

// NAMES [<channel>{,<channel>} [target]]
func namesHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	var channels []string
	if len(msg.Params) > 0 {
		channels = strings.Split(msg.Params[0], ",")
	}

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
		if !channel.flags.HasMode(modes.Secret) || channel.hasClient(client) || client.HasRoleCapabs("sajoin") {
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
func nickHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	newNick := msg.Params[0]
	if client.registered {
		if client.account == "" && server.Config().Accounts.NickReservation.ForbidAnonNickChanges {
			rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.Nick(), client.t("You may not change your nickname"))
			return false
		}
		performNickChange(server, client, client, nil, newNick, rb)
	} else {
		if newNick == "" {
			// #1933: this would leave (*Client).preregNick at its zero value of "",
			// which is the same condition as NICK not having been sent yet ---
			// so we need to send an error immediately
			rb.Add(nil, server.name, ERR_NONICKNAMEGIVEN, "*", client.t("No nickname given"))
			return false
		}
		client.preregNick = newNick
	}
	return false
}

// check whether a PRIVMSG or NOTICE is too long to be relayed without truncation
func validateLineLen(msgType history.ItemType, source, target, payload string) (ok bool) {
	// :source PRIVMSG #target :payload\r\n
	// 1: initial colon on prefix
	// 1: space between prefix and command
	// 1: space between command and target (first parameter)
	// 1: space between target and payload (second parameter)
	// 1: colon to send the payload as a trailing (we force trailing for PRIVMSG and NOTICE)
	// 2: final \r\n
	limit := MaxLineLen - 7
	limit -= len(source)
	switch msgType {
	case history.Privmsg:
		limit -= 7
	case history.Notice:
		limit -= 6
	default:
		return true
	}
	limit -= len(target)
	limit -= len(payload)
	return limit >= 0
}

// check validateLineLen for an entire SplitMessage (which may consist of multiple lines)
func validateSplitMessageLen(msgType history.ItemType, source, target string, message utils.SplitMessage) (ok bool) {
	if message.Is512() {
		return validateLineLen(msgType, source, target, message.Message)
	} else {
		for _, messagePair := range message.Split {
			if !validateLineLen(msgType, source, target, messagePair.Message) {
				return false
			}
		}
		return true
	}
}

// helper to store a batched PRIVMSG in the session object
func absorbBatchedMessage(server *Server, client *Client, msg ircmsg.Message, batchTag string, histType history.ItemType, rb *ResponseBuffer) {
	var failParams []string
	defer func() {
		if failParams != nil {
			if histType != history.Notice {
				params := make([]string, 1+len(failParams))
				params[0] = "BATCH"
				copy(params[1:], failParams)
				rb.Add(nil, server.name, "FAIL", params...)
			}
			rb.session.EndMultilineBatch("")
		}
	}()

	if batchTag != rb.session.batch.label {
		failParams = []string{"MULTILINE_INVALID", client.t("Incorrect batch tag sent")}
		return
	} else if len(msg.Params) < 2 {
		failParams = []string{"MULTILINE_INVALID", client.t("Invalid multiline batch")}
		return
	}
	rb.session.batch.command = msg.Command
	isConcat, _ := msg.GetTag(caps.MultilineConcatTag)
	if isConcat && len(msg.Params[1]) == 0 {
		failParams = []string{"MULTILINE_INVALID", client.t("Cannot send a blank line with the multiline concat tag")}
		return
	}
	if !isConcat && len(rb.session.batch.message.Split) != 0 {
		rb.session.batch.lenBytes++ // bill for the newline
	}
	rb.session.batch.message.Append(msg.Params[1], isConcat)
	rb.session.batch.lenBytes += len(msg.Params[1])
	config := server.Config()
	if config.Limits.Multiline.MaxBytes < rb.session.batch.lenBytes {
		failParams = []string{
			"MULTILINE_MAX_BYTES",
			strconv.Itoa(config.Limits.Multiline.MaxBytes),
			fmt.Sprintf(client.t("Multiline batch byte limit %d exceeded"), config.Limits.Multiline.MaxBytes),
		}
	} else if config.Limits.Multiline.MaxLines != 0 && config.Limits.Multiline.MaxLines < rb.session.batch.message.LenLines() {
		failParams = []string{
			"MULTILINE_MAX_LINES",
			strconv.Itoa(config.Limits.Multiline.MaxLines),
			fmt.Sprintf(client.t("Multiline batch line limit %d exceeded"), config.Limits.Multiline.MaxLines),
		}
	}
}

// NOTICE <target>{,<target>} <message>
// PRIVMSG <target>{,<target>} <message>
// TAGMSG <target>{,<target>}
func messageHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	histType, err := msgCommandToHistType(msg.Command)
	if err != nil {
		return false
	}

	if isBatched, batchTag := msg.GetTag("batch"); isBatched {
		absorbBatchedMessage(server, client, msg, batchTag, histType, rb)
		return false
	}

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
		rb.Add(nil, server.name, ERR_NOTEXTTOSEND, client.Nick(), client.t("No text to send"))
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

		config := server.Config()
		if config.isRelaymsgIdentifier(targetString) {
			if histType == history.Privmsg {
				rb.Add(nil, server.name, ERR_NOSUCHNICK, client.Nick(), targetString, client.t("Relayed users cannot receive private messages"))
			}
			// TAGMSG/NOTICEs are intentionally silently dropped
			continue
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
	} else if target[0] == '$' && len(target) > 2 && client.Oper().HasRoleCapab("massmessage") {
		details := client.Details()
		matcher, err := utils.CompileGlob(target[2:], false)
		if err != nil {
			rb.Add(nil, server.name, ERR_UNKNOWNERROR, details.nick, command, client.t("Erroneous target"))
			return
		}

		nickMaskString := details.nickMask
		accountName := details.accountName
		isBot := client.HasMode(modes.Bot)
		for _, tClient := range server.clients.AllClients() {
			if (target[1] == '$' && matcher.MatchString(tClient.server.name)) || // $$servername
				(target[1] == '#' && matcher.MatchString(tClient.Hostname())) { // $#hostname

				tnick := tClient.Nick()
				for _, session := range tClient.Sessions() {
					session.sendSplitMsgFromClientInternal(false, nickMaskString, accountName, isBot, nil, command, tnick, message)
				}
			}
		}
	} else {
		lowercaseTarget := strings.ToLower(target)
		service, isService := ErgoServices[lowercaseTarget]
		_, isZNC := zncHandlers[lowercaseTarget]

		if isService || isZNC {
			details := client.Details()
			rb.addEchoMessage(tags, details.nickMask, details.accountName, command, target, message)
			if histType != history.Privmsg {
				return // NOTICE and TAGMSG to services are ignored
			}
			if isService {
				servicePrivmsgHandler(service, server, client, message.Message, rb)
			} else if isZNC {
				zncPrivmsgHandler(client, lowercaseTarget, message.Message, rb)
			}
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
		if details.account == "" && server.Defcon() <= 3 {
			rb.Add(nil, server.name, ERR_NEEDREGGEDNICK, client.Nick(), tnick, client.t("Direct messages from unregistered users are temporarily restricted"))
			return
		}
		// restrict messages appropriately when +R is set
		if details.account == "" && user.HasMode(modes.RegisteredOnly) && !server.accepts.MaySendTo(client, user) {
			rb.Add(nil, server.name, ERR_NEEDREGGEDNICK, client.Nick(), tnick, client.t("You must be registered to send a direct message to this user"))
			return
		}
		if client.HasMode(modes.RegisteredOnly) && tDetails.account == "" {
			// #1688: auto-ACCEPT on DM
			server.accepts.Accept(client, user)
		}
		if !client.server.Config().Server.Compatibility.allowTruncation {
			if !validateSplitMessageLen(histType, client.NickMaskString(), tnick, message) {
				rb.Add(nil, server.name, ERR_INPUTTOOLONG, client.Nick(), client.t("Line too long to be relayed without truncation"))
				return
			}
		}
		nickMaskString := details.nickMask
		accountName := details.accountName
		var deliverySessions []*Session
		deliverySessions = append(deliverySessions, user.Sessions()...)
		// all sessions of the sender, except the originating session, get a copy as well:
		if client != user {
			for _, session := range client.Sessions() {
				if session != rb.session {
					deliverySessions = append(deliverySessions, session)
				}
			}
		}

		isBot := client.HasMode(modes.Bot)
		for _, session := range deliverySessions {
			hasTagsCap := session.capabilities.Has(caps.MessageTags)
			// don't send TAGMSG at all if they don't have the tags cap
			if histType == history.Tagmsg && hasTagsCap {
				session.sendFromClientInternal(false, message.Time, message.Msgid, nickMaskString, accountName, isBot, tags, command, tnick)
			} else if histType != history.Tagmsg && !(session.isTor && message.IsRestrictedCTCPMessage()) {
				tagsToSend := tags
				if !hasTagsCap {
					tagsToSend = nil
				}
				session.sendSplitMsgFromClientInternal(false, nickMaskString, accountName, isBot, tagsToSend, command, tnick, message)
			}
		}

		// the originating session may get an echo message:
		rb.addEchoMessage(tags, nickMaskString, accountName, command, tnick, message)
		if histType == history.Privmsg {
			//TODO(dan): possibly implement cooldown of away notifications to users
			if away, awayMessage := user.Away(); away {
				rb.Add(nil, server.name, RPL_AWAY, client.Nick(), tnick, awayMessage)
			}
		}

		config := server.Config()
		if !config.History.Enabled {
			return
		}
		item := history.Item{
			Type:    histType,
			Message: message,
			Tags:    tags,
		}
		client.addHistoryItem(user, item, &details, &tDetails, config)

		if config.WebPush.Enabled && histType != history.Tagmsg && user.hasPushSubscriptions() {
			pushMsgBytes, err := webpush.MakePushMessage(command, nickMaskString, accountName, tnick, message)
			if err == nil {
				user.dispatchPushMessage(pushMessage{msg: pushMsgBytes, urgency: webpush.UrgencyHigh})
			} else {
				server.logger.Error("internal", "can't serialize push message", err.Error())
			}
		}
	}
}

func itemIsStorable(item *history.Item, config *Config) bool {
	switch item.Type {
	case history.Tagmsg:
		if config.History.TagmsgStorage.Default {
			for _, blacklistedTag := range config.History.TagmsgStorage.Blacklist {
				if _, ok := item.Tags[blacklistedTag]; ok {
					return false
				}
			}
			return true
		} else {
			for _, whitelistedTag := range config.History.TagmsgStorage.Whitelist {
				if _, ok := item.Tags[whitelistedTag]; ok {
					return true
				}
			}
			return false
		}
	case history.Privmsg, history.Notice:
		// don't store CTCP other than ACTION
		return !item.Message.IsRestrictedCTCPMessage()
	default:
		return true
	}
}

// NPC <target> <sourcenick> <message>
func npcHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	target := msg.Params[0]
	fakeSource := msg.Params[1]
	message := msg.Params[2:]

	sendRoleplayMessage(server, client, fakeSource, target, false, false, message, rb)

	return false
}

// NPCA <target> <sourcenick> <message>
func npcaHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	target := msg.Params[0]
	fakeSource := msg.Params[1]
	message := msg.Params[2:]

	sendRoleplayMessage(server, client, fakeSource, target, false, true, message, rb)

	return false
}

// OPER <name> [password]
func operHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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

		client.server.logger.Info("opers", details.nick, "opered up as", oper.Name)
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
func deoperHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	if client.Oper() == nil {
		rb.Notice(client.t("Insufficient oper privs"))
		return false
	}
	// pretend they sent /MODE $nick -o
	fakeModeMsg := ircmsg.MakeMessage(nil, "", "MODE", client.Nick(), "-o")
	return umodeHandler(server, client, fakeModeMsg, rb)
}

// PART <channel>{,<channel>} [<reason>]
func partHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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
func passHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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
				sendSuccessfulAccountAuth(nil, client, rb, true)
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

// PERSISTENCE <subcommand> [params...]
func persistenceHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	account := client.Account()
	if account == "" {
		rb.Add(nil, server.name, "FAIL", "PERSISTENCE", "ACCOUNT_REQUIRED", client.t("You're not logged into an account"))
		return false
	}

	switch strings.ToUpper(msg.Params[0]) {
	case "GET":
		reportPersistenceStatus(client, rb, false)
	case "SET":
		if len(msg.Params) == 1 {
			goto fail
		}
		var desiredSetting PersistentStatus
		switch strings.ToUpper(msg.Params[1]) {
		case "DEFAULT":
			desiredSetting = PersistentUnspecified
		case "OFF":
			desiredSetting = PersistentDisabled
		case "ON":
			desiredSetting = PersistentMandatory
		default:
			goto fail
		}

		broadcast := false
		_, err := server.accounts.ModifyAccountSettings(account,
			func(input AccountSettings) (output AccountSettings, err error) {
				output = input
				output.AlwaysOn = desiredSetting
				broadcast = output.AlwaysOn != input.AlwaysOn
				return
			})
		if err != nil {
			server.logger.Error("internal", "couldn't modify persistence setting", err.Error())
			rb.Add(nil, server.name, "FAIL", "PERSISTENCE", "UNKNOWN_ERROR", client.t("An error occurred"))
			return false
		}

		reportPersistenceStatus(client, rb, broadcast)

	default:
		goto fail
	}

	return false

fail:
	rb.Add(nil, server.name, "FAIL", "PERSISTENCE", "INVALID_PARAMS", client.t("Invalid parameters"))
	return false
}

// REDACT <target> <targetmsgid> [:<reason>]
func redactHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	target := msg.Params[0]
	targetmsgid := msg.Params[1]
	//clientOnlyTags := msg.ClientOnlyTags()
	var reason string
	if len(msg.Params) > 2 {
		reason = msg.Params[2]
	}
	var members []*Client // members of a channel, or both parties of a PM
	var canDelete CanDelete

	msgid := utils.GenerateSecretToken()
	time := time.Now().UTC().Round(0)
	details := client.Details()
	isBot := client.HasMode(modes.Bot)

	if target[0] == '#' {
		channel := server.channels.Get(target)
		if channel == nil {
			rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.Nick(), utils.SafeErrorParam(target), client.t("No such channel"))
			return false
		}
		members = channel.Members()
		canDelete = deletionPolicy(server, client, target)
	} else {
		targetClient := server.clients.Get(target)
		if targetClient == nil {
			rb.Add(nil, server.name, ERR_NOSUCHNICK, client.Nick(), target, "No such nick")
			return false
		}
		members = []*Client{client, targetClient}
		canDelete = canDeleteSelf
	}

	if canDelete == canDeleteNone {
		rb.Add(nil, server.name, "FAIL", "REDACT", "REDACT_FORBIDDEN", utils.SafeErrorParam(target), utils.SafeErrorParam(targetmsgid), client.t("You are not authorized to delete messages"))
		return false
	}
	accountName := "*"
	if canDelete == canDeleteSelf {
		accountName = client.AccountName()
		if accountName == "*" {
			rb.Add(nil, server.name, "FAIL", "REDACT", "REDACT_FORBIDDEN", utils.SafeErrorParam(target), utils.SafeErrorParam(targetmsgid), client.t("You are not authorized to delete this message"))
			return false
		}
	}

	err := server.DeleteMessage(target, targetmsgid, accountName)
	if err == errNoop {
		rb.Add(nil, server.name, "FAIL", "REDACT", "UNKNOWN_MSGID", utils.SafeErrorParam(target), utils.SafeErrorParam(targetmsgid), client.t("This message does not exist or is too old"))
		return false
	} else if err != nil {
		isOper := client.HasRoleCapabs("history")
		if isOper {
			rb.Add(nil, server.name, "FAIL", "REDACT", "REDACT_FORBIDDEN", utils.SafeErrorParam(target), utils.SafeErrorParam(targetmsgid), fmt.Sprintf(client.t("Error deleting message: %v"), err))
		} else {
			rb.Add(nil, server.name, "FAIL", "REDACT", "REDACT_FORBIDDEN", utils.SafeErrorParam(target), utils.SafeErrorParam(targetmsgid), client.t("Could not delete message"))
		}
		return false
	}

	if target[0] != '#' {
		// If this is a PM, we just removed the message from the buffer of the other party;
		// now we have to remove it from the buffer of the client who sent the REDACT command
		err := server.DeleteMessage(client.Nick(), targetmsgid, accountName)

		if err != nil {
			client.server.logger.Error("internal", fmt.Sprintf("Private message %s is not deletable by %s from their own buffer's even though we just deleted it from %s's. This is a bug, please report it in details.", targetmsgid, client.Nick(), target), client.Nick())
			isOper := client.HasRoleCapabs("history")
			if isOper {
				rb.Add(nil, server.name, "FAIL", "REDACT", "REDACT_FORBIDDEN", utils.SafeErrorParam(target), utils.SafeErrorParam(targetmsgid), fmt.Sprintf(client.t("Error deleting message: %v"), err))
			} else {
				rb.Add(nil, server.name, "FAIL", "REDACT", "REDACT_FORBIDDEN", utils.SafeErrorParam(target), utils.SafeErrorParam(targetmsgid), client.t("Error deleting message"))
			}
		}
	}

	for _, member := range members {
		for _, session := range member.Sessions() {
			if session.capabilities.Has(caps.MessageRedaction) {
				session.sendFromClientInternal(false, time, msgid, details.nickMask, details.accountName, isBot, nil, "REDACT", target, targetmsgid, reason)
			} else {
				// If we wanted to send a fallback to clients which do not support
				// draft/message-redaction, we would do it from here.
			}
		}
	}
	return false
}

func reportPersistenceStatus(client *Client, rb *ResponseBuffer, broadcast bool) {
	settings := client.AccountSettings()
	serverSetting := client.server.Config().Accounts.Multiclient.AlwaysOn
	effectiveSetting := persistenceEnabled(serverSetting, settings.AlwaysOn)
	toString := func(setting PersistentStatus) string {
		switch setting {
		case PersistentUnspecified:
			return "DEFAULT"
		case PersistentDisabled:
			return "OFF"
		case PersistentMandatory:
			return "ON"
		default:
			return "*" // impossible
		}
	}
	storedSettingStr := toString(settings.AlwaysOn)
	effectiveSettingStr := "OFF"
	if effectiveSetting {
		effectiveSettingStr = "ON"
	}
	rb.Add(nil, client.server.name, "PERSISTENCE", "STATUS", storedSettingStr, effectiveSettingStr)
	if broadcast {
		for _, session := range client.Sessions() {
			if session != rb.session && session.capabilities.Has(caps.Persistence) {
				session.Send(nil, client.server.name, "PERSISTENCE", "STATUS", storedSettingStr, effectiveSettingStr)
			}
		}
	}
}

// PING [params...]
func pingHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	rb.Add(nil, server.name, "PONG", server.name, msg.Params[0])
	return false
}

// PONG [params...]
func pongHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	// client gets touched when they send this command, so we don't need to do anything
	return false
}

// QUIT [<reason>]
func quitHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	reason := "Quit"
	if len(msg.Params) > 0 {
		reason += ": " + msg.Params[0]
	}
	client.Quit(reason, rb.session)
	return true
}

// REGISTER < account | * > < email | * > <password>
func registerHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) (exiting bool) {
	accountName := client.Nick()
	if accountName == "*" {
		accountName = client.preregNick
	}

	switch msg.Params[0] {
	case "*", accountName:
		// ok
	default:
		rb.Add(nil, server.name, "FAIL", "REGISTER", "ACCOUNT_NAME_MUST_BE_NICK", utils.SafeErrorParam(msg.Params[0]), client.t("You may only register your nickname as your account name"))
		return
	}

	// check that accountName is valid as a non-final parameter;
	// this is necessary for us to be valid and it will prevent us from emitting invalid error lines
	nickErrorParam := utils.SafeErrorParam(accountName)
	if accountName == "*" || accountName != nickErrorParam {
		rb.Add(nil, server.name, "FAIL", "REGISTER", "INVALID_USERNAME", nickErrorParam, client.t("Username invalid or not given"))
		return
	}

	config := server.Config()
	if !config.Accounts.Registration.Enabled {
		rb.Add(nil, server.name, "FAIL", "REGISTER", "DISALLOWED", accountName, client.t("Account registration is disabled"))
		return
	}
	if !client.registered && !config.Accounts.Registration.AllowBeforeConnect {
		rb.Add(nil, server.name, "FAIL", "REGISTER", "COMPLETE_CONNECTION_REQUIRED", accountName, client.t("You must complete the connection before registering your account"))
		return
	}
	if client.registerCmdSent || client.Account() != "" {
		rb.Add(nil, server.name, "FAIL", "REGISTER", "ALREADY_REGISTERED", accountName, client.t("You have already registered or attempted to register"))
		return
	}

	callbackNamespace, callbackValue, err := parseCallback(msg.Params[1], config)
	if err != nil {
		rb.Add(nil, server.name, "FAIL", "REGISTER", "INVALID_EMAIL", accountName, client.t("A valid e-mail address is required"))
		return
	}

	err = server.accounts.Register(client, accountName, callbackNamespace, callbackValue, msg.Params[2], rb.session.certfp)
	switch err {
	case nil:
		if callbackNamespace == "*" {
			err := server.accounts.Verify(client, accountName, "", true)
			if err == nil {
				if client.registered {
					if !fixupNickEqualsAccount(client, rb, config, "") {
						err = errNickAccountMismatch
					}
				}
				if err == nil {
					rb.Add(nil, server.name, "REGISTER", "SUCCESS", accountName, client.t("Account successfully registered"))
					sendSuccessfulRegResponse(nil, client, rb)
				}
			}
			if err != nil {
				server.logger.Error("internal", "accounts", "failed autoverification", accountName, err.Error())
				rb.Add(nil, server.name, "FAIL", "REGISTER", "UNKNOWN_ERROR", client.t("An error occurred"))
			}
		} else {
			rb.Add(nil, server.name, "REGISTER", "VERIFICATION_REQUIRED", accountName, fmt.Sprintf(client.t("Account created, pending verification; verification code has been sent to %s"), callbackValue))
			client.registerCmdSent = true
			announcePendingReg(client, rb, accountName)
		}
	case errAccountAlreadyRegistered, errAccountAlreadyUnregistered, errAccountMustHoldNick:
		rb.Add(nil, server.name, "FAIL", "REGISTER", "USERNAME_EXISTS", accountName, client.t("Username is already registered or otherwise unavailable"))
	case errAccountBadPassphrase:
		rb.Add(nil, server.name, "FAIL", "REGISTER", "INVALID_PASSWORD", accountName, client.t("Password was invalid"))
	default:
		if emailError := registrationCallbackErrorText(config, client, err); emailError != "" {
			rb.Add(nil, server.name, "FAIL", "REGISTER", "UNACCEPTABLE_EMAIL", accountName, emailError)
		} else {
			rb.Add(nil, server.name, "FAIL", "REGISTER", "UNKNOWN_ERROR", accountName, client.t("Could not register"))
		}
	}
	return
}

// VERIFY <account> <code>
func verifyHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) (exiting bool) {
	config := server.Config()
	if !config.Accounts.Registration.Enabled {
		rb.Add(nil, server.name, "FAIL", "VERIFY", "DISALLOWED", client.t("Account registration is disabled"))
		return
	}
	if !client.registered && !config.Accounts.Registration.AllowBeforeConnect {
		rb.Add(nil, server.name, "FAIL", "VERIFY", "DISALLOWED", client.t("You must complete the connection before verifying your account"))
		return
	}
	if client.Account() != "" {
		rb.Add(nil, server.name, "FAIL", "VERIFY", "ALREADY_REGISTERED", client.t("You have already registered or attempted to register"))
		return
	}

	accountName, verificationCode := msg.Params[0], msg.Params[1]
	err := server.accounts.Verify(client, accountName, verificationCode, false)
	if err == nil && client.registered {
		if !fixupNickEqualsAccount(client, rb, config, "") {
			err = errNickAccountMismatch
		}
	}
	switch err {
	case nil:
		rb.Add(nil, server.name, "VERIFY", "SUCCESS", accountName, client.t("Account successfully registered"))
		sendSuccessfulRegResponse(nil, client, rb)
	case errAccountVerificationInvalidCode:
		rb.Add(nil, server.name, "FAIL", "VERIFY", "INVALID_CODE", client.t("Invalid verification code"))
	default:
		rb.Add(nil, server.name, "FAIL", "VERIFY", "UNKNOWN_ERROR", client.t("Failed to verify account"))
	}

	if err != nil && !client.registered {
		// XXX pre-registration clients are exempt from fakelag;
		// slow the client down to stop them spamming verify attempts
		time.Sleep(time.Second)
	}

	return
}

// MARKREAD <target> [timestamp]
func markReadHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) (exiting bool) {
	if len(msg.Params) == 0 {
		rb.Add(nil, server.name, "FAIL", "MARKREAD", "NEED_MORE_PARAMS", client.t("Missing parameters"))
		return
	}

	target := msg.Params[0]
	cftarget, err := CasefoldTarget(target)
	if err != nil {
		rb.Add(nil, server.name, "FAIL", "MARKREAD", "INVALID_PARAMS", utils.SafeErrorParam(target), client.t("Invalid target"))
		return
	}
	unfoldedTarget := server.UnfoldName(cftarget)

	// "MARKREAD client get command": MARKREAD <target>
	if len(msg.Params) == 1 {
		rb.Add(nil, client.server.name, "MARKREAD", unfoldedTarget, client.GetReadMarker(cftarget))
		return
	}

	// "MARKREAD client set command": MARKREAD <target> <timestamp>
	readTimestamp := strings.TrimPrefix(msg.Params[1], "timestamp=")
	readTime, err := time.Parse(IRCv3TimestampFormat, readTimestamp)
	if err != nil {
		rb.Add(nil, server.name, "FAIL", "MARKREAD", "INVALID_PARAMS", utils.SafeErrorParam(readTimestamp), client.t("Invalid timestamp"))
		return
	}
	result := client.SetReadMarker(cftarget, readTime)
	readTimestamp = fmt.Sprintf("timestamp=%s", result.Format(IRCv3TimestampFormat))
	// inform the originating session whether it was a success or a no-op:
	rb.Add(nil, server.name, "MARKREAD", unfoldedTarget, readTimestamp)
	if result.Equal(readTime) {
		// successful update (i.e. it moved the stored timestamp forward):
		// inform other sessions
		for _, session := range client.Sessions() {
			if session != rb.session && session.capabilities.Has(caps.ReadMarker) {
				session.Send(nil, server.name, "MARKREAD", unfoldedTarget, readTimestamp)
			}
		}
		// TODO add support for pushing MARKREAD
	}
	return
}

// REHASH
func rehashHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, nick, "REHASH", ircutils.SanitizeText(err.Error(), 350))
	}
	return false
}

// RELAYMSG <channel> <spoofed nick> :<message>
func relaymsgHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) (result bool) {
	config := server.Config()
	if !config.Server.Relaymsg.Enabled {
		rb.Add(nil, server.name, "FAIL", "RELAYMSG", "NOT_ENABLED", client.t("RELAYMSG has been disabled"))
		return false
	}

	channel := server.channels.Get(msg.Params[0])
	if channel == nil {
		rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.Nick(), utils.SafeErrorParam(msg.Params[0]), client.t("No such channel"))
		return false
	}

	allowedToRelay := client.HasRoleCapabs("relaymsg") || (config.Server.Relaymsg.AvailableToChanops && channel.ClientIsAtLeast(client, modes.ChannelOperator))
	if !allowedToRelay {
		rb.Add(nil, server.name, "FAIL", "RELAYMSG", "PRIVS_NEEDED", client.t("You cannot relay messages to this channel"))
		return false
	}

	rawMessage := msg.Params[2]
	if strings.TrimSpace(rawMessage) == "" {
		rb.Add(nil, server.name, "FAIL", "RELAYMSG", "BLANK_MSG", client.t("The message must not be blank"))
		return false
	}
	message := utils.MakeMessage(rawMessage)

	nick := msg.Params[1]
	cfnick, err := CasefoldName(nick)
	if err != nil {
		rb.Add(nil, server.name, "FAIL", "RELAYMSG", "INVALID_NICK", client.t("Invalid nickname"))
		return false
	}
	if !config.isRelaymsgIdentifier(nick) {
		rb.Add(nil, server.name, "FAIL", "RELAYMSG", "INVALID_NICK", fmt.Sprintf(client.t("Relayed nicknames MUST contain a relaymsg separator from this set: %s"), config.Server.Relaymsg.Separators))
		return false
	}
	if channel.relayNickMuted(cfnick) {
		rb.Add(nil, server.name, "FAIL", "RELAYMSG", "BANNED", fmt.Sprintf(client.t("%s is banned from relaying to the channel"), nick))
		return false
	}

	details := client.Details()
	// #1647: we need to publish a full NUH. send ~u (or the configured alternative)
	// as the user/ident, and send the relayer's hostname as the hostname:
	ident := config.Server.CoerceIdent
	if ident == "" {
		ident = "~u"
	}
	// #1661: if the bot has its own account, use the account cloak,
	// otherwise fall back to the hostname (which may be IP-derived)
	hostname := details.hostname
	if details.accountName != "" {
		hostname = config.Server.Cloaks.ComputeAccountCloak(details.accountName)
	}
	nuh := fmt.Sprintf("%s!%s@%s", nick, ident, hostname)

	channel.AddHistoryItem(history.Item{
		Type:    history.Privmsg,
		Message: message,
		Nick:    nuh,
	}, "")

	// 3 possibilities for tags:
	// no tags, the relaymsg tag only, or the relaymsg tag together with all client-only tags
	relayTag := map[string]string{
		caps.RelaymsgTagName: details.nick,
	}
	clientOnlyTags := msg.ClientOnlyTags()
	var fullTags map[string]string
	if len(clientOnlyTags) == 0 {
		fullTags = relayTag
	} else {
		fullTags = make(map[string]string, 1+len(clientOnlyTags))
		fullTags[caps.RelaymsgTagName] = details.nick
		for t, v := range clientOnlyTags {
			fullTags[t] = v
		}
	}

	// actually send the message
	channelName := channel.Name()
	for _, member := range channel.Members() {
		for _, session := range member.Sessions() {
			var tagsToUse map[string]string
			if session.capabilities.Has(caps.MessageTags) {
				tagsToUse = fullTags
			} else if session.capabilities.Has(caps.Relaymsg) {
				tagsToUse = relayTag
			}

			if session == rb.session {
				rb.AddSplitMessageFromClient(nuh, "*", false, tagsToUse, "PRIVMSG", channelName, message)
			} else {
				session.sendSplitMsgFromClientInternal(false, nuh, "*", false, tagsToUse, "PRIVMSG", channelName, message)
			}
		}
	}
	return false
}

// RENAME <oldchan> <newchan> [<reason>]
func renameHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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
	oldName = channel.Name()

	if !(channel.ClientIsAtLeast(client, modes.ChannelOperator) || client.HasRoleCapabs("chanreg")) {
		rb.Add(nil, server.name, ERR_CHANOPRIVSNEEDED, client.Nick(), oldName, client.t("You're not a channel operator"))
		return false
	}

	founder := channel.Founder()
	if founder != "" && founder != client.Account() {
		rb.Add(nil, server.name, "FAIL", "RENAME", "CANNOT_RENAME", oldName, utils.SafeErrorParam(newName), client.t("Only channel founders can change registered channels"))
		return false
	}

	config := server.Config()
	status, _, _ := channel.historyStatus(config)
	if status == HistoryPersistent {
		rb.Add(nil, server.name, "FAIL", "RENAME", "CANNOT_RENAME", oldName, utils.SafeErrorParam(newName), client.t("Channels with persistent history cannot be renamed"))
		return false
	}

	// perform the channel rename
	err := server.channels.Rename(oldName, newName)
	if err == errInvalidChannelName {
		rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.Nick(), utils.SafeErrorParam(newName), client.t(err.Error()))
	} else if err == errChannelNameInUse || err == errConfusableIdentifier {
		rb.Add(nil, server.name, "FAIL", "RENAME", "CHANNEL_NAME_IN_USE", oldName, utils.SafeErrorParam(newName), client.t(err.Error()))
	} else if err != nil {
		rb.Add(nil, server.name, "FAIL", "RENAME", "CANNOT_RENAME", oldName, utils.SafeErrorParam(newName), client.t("Cannot rename channel"))
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
			if mSession.capabilities.Has(caps.ChannelRename) {
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
				if !targetRb.session.capabilities.Has(caps.NoImplicitNames) {
					channel.Names(mcl, targetRb)
				}
			}
			if mcl != client {
				targetRb.Send(false)
			}
		}
	}

	return false
}

// SANICK <oldnick> <nickname>
func sanickHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	targetNick := msg.Params[0]
	target := server.clients.Get(targetNick)
	if target == nil {
		rb.Add(nil, server.name, "FAIL", "SANICK", "NO_SUCH_NICKNAME", utils.SafeErrorParam(targetNick), client.t("No such nick"))
		return false
	}
	performNickChange(server, client, target, nil, msg.Params[1], rb)
	return false
}

// SCENE <target> <message>
func sceneHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	target := msg.Params[0]
	message := msg.Params[1:]

	sendRoleplayMessage(server, client, "", target, true, false, message, rb)

	return false
}

// SETNAME <realname>
func setnameHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	realname := msg.Params[0]
	if len(msg.Params) != 1 {
		// workaround for clients that turn unknown commands into raw IRC lines,
		// so you can do `/setname Jane Doe` in the client and get the expected result
		realname = strings.Join(msg.Params, " ")
	}
	if realname == "" {
		rb.Add(nil, server.name, "FAIL", "SETNAME", "INVALID_REALNAME", client.t("Realname is not valid"))
		return false
	}

	client.SetRealname(realname)
	details := client.Details()

	// alert friends
	now := time.Now().UTC()
	friends := client.FriendsMonitors(caps.SetName)
	delete(friends, rb.session)
	isBot := client.HasMode(modes.Bot)
	for session := range friends {
		session.sendFromClientInternal(false, now, "", details.nickMask, details.accountName, isBot, nil, "SETNAME", details.realname)
	}
	// respond to the user unconditionally, even if they don't have the cap
	rb.AddFromClient(now, "", details.nickMask, details.accountName, isBot, nil, "SETNAME", details.realname)
	return false
}

// SUMMON [parameters]
func summonHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	rb.Add(nil, server.name, ERR_SUMMONDISABLED, client.Nick(), client.t("SUMMON has been disabled"))
	return false
}

// TIME
func timeHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	rb.Add(nil, server.name, RPL_TIME, client.nick, server.name, time.Now().UTC().Format(time.RFC1123))
	return false
}

// TOPIC <channel> [<topic>]
func topicHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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
func unDLineHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	// check oper permissions
	oper := client.Oper()
	if !oper.HasRoleCapab("ban") {
		rb.Add(nil, server.name, ERR_NOPRIVS, client.nick, msg.Command, client.t("Insufficient oper privs"))
		return false
	}

	// get host
	hostString := msg.Params[0]

	// check host
	hostNet, err := flatip.ParseToNormalizedNet(hostString)

	if err != nil {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("Could not parse IP address or CIDR network"))
		return false
	}

	err = server.dlines.RemoveNetwork(hostNet)

	if err != nil {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, fmt.Sprintf(client.t("Could not remove ban [%s]"), err.Error()))
		return false
	}

	hostString = hostNet.String()
	rb.Notice(fmt.Sprintf(client.t("Removed D-Line for %s"), hostString))
	server.snomasks.Send(sno.LocalXline, fmt.Sprintf(ircfmt.Unescape("%s$r removed D-Line for %s"), client.nick, hostString))
	return false
}

// UNKLINE <mask>
func unKLineHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	details := client.Details()
	// check oper permissions
	oper := client.Oper()
	if !oper.HasRoleCapab("ban") {
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
func userHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	if client.registered {
		rb.Add(nil, server.name, ERR_ALREADYREGISTRED, client.Nick(), client.t("You may not reregister"))
		return false
	}

	username, realname := msg.Params[0], msg.Params[3]
	if len(realname) == 0 {
		rb.Add(nil, server.name, ERR_NEEDMOREPARAMS, client.Nick(), "USER", client.t("Not enough parameters"))
		return false
	}
	config := server.Config()
	if config.Limits.RealnameLen > 0 && len(realname) > config.Limits.RealnameLen {
		realname = ircmsg.TruncateUTF8Safe(realname, config.Limits.RealnameLen)
	}

	// #843: we accept either: `USER user:pass@clientid` or `USER user@clientid`
	if strudelIndex := strings.IndexByte(username, '@'); strudelIndex != -1 {
		username, rb.session.deviceID = username[:strudelIndex], username[strudelIndex+1:]
		if colonIndex := strings.IndexByte(username, ':'); colonIndex != -1 {
			var password string
			username, password = username[:colonIndex], username[colonIndex+1:]
			err := server.accounts.AuthenticateByPassphrase(client, username, password)
			if err == nil {
				sendSuccessfulAccountAuth(nil, client, rb, true)
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

// does `target` have an operator status that is visible to `client`?
func operStatusVisible(client, target *Client, hasPrivs bool) bool {
	targetOper := target.Oper()
	if targetOper == nil {
		return false
	}
	if client == target || hasPrivs {
		return true
	}
	return !targetOper.Hidden
}

// USERHOST <nickname>{ <nickname>}
func userhostHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	hasPrivs := client.HasMode(modes.Operator)
	returnedClients := make(ClientSet)

	var tl utils.TokenLineBuilder
	tl.Initialize(maxLastArgLength, " ")
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

		if operStatusVisible(client, target, hasPrivs) {
			isOper = "*"
		}
		if away, _ := target.Away(); away {
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
func usersHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	rb.Add(nil, server.name, ERR_USERSDISABLED, client.Nick(), client.t("USERS has been disabled"))
	return false
}

// VERSION
func versionHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	rb.Add(nil, server.name, RPL_VERSION, client.nick, Ver, server.name)
	server.RplISupport(client, rb)
	return false
}

// WEBIRC <password> <gateway> <hostname> <ip> [:flag1 flag2=x flag3]
func webircHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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

	config := server.Config()
	givenPassword := []byte(msg.Params[0])
	for _, info := range config.Server.WebIRC {
		if utils.IPInNets(client.realIP, info.allowedNets) {
			// confirm password and/or fingerprint
			if 0 < len(info.Password) && bcrypt.CompareHashAndPassword(info.Password, givenPassword) != nil {
				continue
			}
			if info.Certfp != "" && info.Certfp != rb.session.certfp {
				continue
			}

			candidateIP := msg.Params[3]
			err, quitMsg := client.ApplyProxiedIP(rb.session, net.ParseIP(candidateIP), secure)
			if err != nil {
				client.Quit(quitMsg, rb.session)
				return true
			} else {
				if info.AcceptHostname {
					candidateHostname := msg.Params[2]
					if candidateHostname != candidateIP {
						if utils.IsHostname(candidateHostname) {
							rb.session.rawHostname = candidateHostname
						} else {
							// log this at debug level since it may be spammy
							server.logger.Debug("internal", "invalid hostname from WEBIRC", candidateHostname)
						}
					}
				}
				return false
			}
		}
	}

	client.Quit(client.t("WEBIRC command is not usable from your address or incorrect password given"), rb.session)
	return true
}

// WEBPUSH <subcommand> <endpoint> [key]
func webpushHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	subcommand := strings.ToUpper(msg.Params[0])

	config := server.Config()
	if !config.WebPush.Enabled {
		rb.Add(nil, server.name, "FAIL", "WEBPUSH", "FORBIDDEN", subcommand, client.t("Web push is disabled"))
		return false
	}

	if client.Account() == "" {
		rb.Add(nil, server.name, "FAIL", "WEBPUSH", "FORBIDDEN", subcommand, client.t("You must be logged in to receive push messages"))
		return false
	}

	// XXX web push can be used to deanonymize a Tor hidden service, but we do not know
	// whether an Ergo deployment with a Tor listener is intended to run as a hidden
	// service, or as a single onion service where Tor is optional. Hidden service operators
	// should disable web push. However, as a sanity check, disallow enabling it over a Tor
	// connection:
	if rb.session.isTor {
		rb.Add(nil, server.name, "FAIL", "WEBPUSH", "FORBIDDEN", subcommand, client.t("Web push cannot be enabled over Tor"))
		return false
	}

	endpoint := msg.Params[1]

	if err := webpush.SanityCheckWebPushEndpoint(endpoint); err != nil {
		rb.Add(nil, server.name, "FAIL", "WEBPUSH", "INVALID_PARAMS", subcommand, client.t("Invalid web push URL"))
	}

	switch subcommand {
	case "REGISTER":
		// allow web push enable even if they are not always-on (they just won't get push messages)
		if len(msg.Params) < 3 {
			rb.Add(nil, server.name, "FAIL", "WEBPUSH", "INVALID_PARAMS", subcommand, client.t("Insufficient parameters for WEBPUSH REGISTER"))
			return false
		}
		keys, err := webpush.DecodeSubscriptionKeys(msg.Params[2])
		if err != nil {
			rb.Add(nil, server.name, "FAIL", "WEBPUSH", "INVALID_PARAMS", subcommand, client.t("Invalid subscription keys for WEBPUSH REGISTER"))
			return false
		}
		if client.refreshPushSubscription(endpoint, keys) {
			// success, don't send a test message
			rb.Add(nil, server.name, "WEBPUSH", "REGISTER", msg.Params[1], msg.Params[2])
			return false
		}
		// send a test message
		if err := client.sendPush(
			endpoint,
			keys,
			webpush.UrgencyHigh,
			webpush.PingMessage,
		); err == nil {
			if err := client.addPushSubscription(endpoint, keys); err == nil {
				rb.Add(nil, server.name, "WEBPUSH", "REGISTER", msg.Params[1], msg.Params[2])
				if !client.AlwaysOn() {
					rb.Add(nil, server.name, "WARN", "WEBPUSH", "PERSISTENCE_REQUIRED", client.t("You have enabled push notifications, but you will not receive them unless you become always-on. Try: /msg nickserv set always-on true"))
				}
			} else if err == errLimitExceeded {
				rb.Add(nil, server.name, "FAIL", "WEBPUSH", "FORBIDDEN", "REGISTER", client.t("You have too many push subscriptions already"))
			} else {
				server.logger.Error("webpush", "Failed to add webpush subscription", err.Error())
				rb.Add(nil, server.name, "FAIL", "WEBPUSH", "INTERNAL_ERROR", "REGISTER", client.t("An error occurred"))
			}
		} else {
			server.logger.Debug("webpush", "WEBPUSH REGISTER failed validation", endpoint, err.Error())
			rb.Add(nil, server.name, "FAIL", "WEBPUSH", "INVALID_PARAMS", "REGISTER", client.t("Test push message failed to send"))
		}
	case "UNREGISTER":
		client.deletePushSubscription(endpoint, true)
		// this always succeeds
		rb.Add(nil, server.name, "WEBPUSH", "UNREGISTER", endpoint)
	}

	return false
}

type whoxFields uint32 // bitset to hold the WHOX field values, 'a' through 'z'

func (fields whoxFields) Add(field rune) (result whoxFields) {
	index := int(field) - int('a')
	if 0 <= index && index < 26 {
		return fields | (1 << index)
	} else {
		return fields
	}
}

func (fields whoxFields) Has(field rune) bool {
	index := int(field) - int('a')
	if 0 <= index && index < 26 {
		return (fields & (1 << index)) != 0
	} else {
		return false
	}
}

// rplWhoReply returns the WHO(X) reply between one user and another channel/user.
// who format:
// <channel> <user> <host> <server> <nick> <H|G>[*][~|&|@|%|+][B] :<hopcount> <real name>
// whox format:
// <type> <channel> <user> <ip> <host> <server> <nick> <H|G>[*][~|&|@|%|+][B] <hops> <idle> <account> <rank> :<real name>
func (client *Client) rplWhoReply(channel *Channel, target *Client, rb *ResponseBuffer, canSeeIPs, canSeeOpers, includeRFlag, isWhox bool, fields whoxFields, whoType string) {
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
		if canSeeIPs || client == target {
			// you can only see a target's IP if they're you or you're an oper
			ip, _ := target.getWhoisActually()
			fIP = utils.IPStringToHostname(ip.String())
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
		if away, _ := target.Away(); away {
			flags.WriteRune('G') // Gone
		} else {
			flags.WriteRune('H') // Here
		}

		if target.HasMode(modes.Operator) && operStatusVisible(client, target, canSeeOpers) {
			flags.WriteRune('*')
		}

		if channel != nil {
			flags.WriteString(channel.ClientPrefixes(target, rb.session.capabilities.Has(caps.MultiPrefix)))
		}

		if target.HasMode(modes.Bot) {
			flags.WriteRune('B')
		}

		if includeRFlag && details.account != "" {
			flags.WriteRune('r')
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
	if fields.Has('o') {
		// channel oplevel, not implemented
		params = append(params, "*")
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

func serviceWhoReply(client *Client, service *ircService, rb *ResponseBuffer, isWhox bool, fields whoxFields, whoType string) {
	params := []string{client.Nick()}

	if fields.Has('t') {
		params = append(params, whoType)
	}
	if fields.Has('c') {
		params = append(params, "*")
	}
	if fields.Has('u') {
		params = append(params, service.Name)
	}
	if fields.Has('i') {
		params = append(params, "127.0.0.1")
	}
	if fields.Has('h') {
		params = append(params, "localhost")
	}
	if fields.Has('s') {
		params = append(params, client.server.name)
	}
	if fields.Has('n') {
		params = append(params, service.Name)
	}
	if fields.Has('f') { // "flags" (away + oper state + channel status prefix + bot)
		params = append(params, "H")
	}
	if fields.Has('d') { // server hops from us to target
		params = append(params, "0")
	}
	if fields.Has('l') { // idle seconds
		params = append(params, "0")
	}
	if fields.Has('a') { // account, services are considered not to have one
		params = append(params, "0")
	}
	if fields.Has('o') { // channel oplevel, not implemented
		params = append(params, "*")
	}
	if fields.Has('r') {
		params = append(params, service.Realname(client))
	}

	numeric := RPL_WHOSPCRPL
	if !isWhox {
		numeric = RPL_WHOREPLY
		// if this isn't WHOX, stick hops + realname at the end
		params = append(params, "0 "+service.Realname(client))
	}

	rb.Add(nil, client.server.name, numeric, params...)
}

// WHO <mask> [<filter>%<fields>,<type>]
func whoHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	origMask := utils.SafeErrorParam(msg.Params[0])
	if origMask != msg.Params[0] {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.Nick(), "WHO", client.t("First param must be a mask or channel"))
		return false
	}

	// https://modern.ircdocs.horse/#who-message
	// "1. A channel name, in which case the channel members are listed."
	// "2. An exact nickname, in which case a single user is returned."
	// "3. A mask pattern, in which case all visible users whose nickname matches are listed."
	var isChannel bool
	var isBareNick bool
	mask := origMask
	var err error
	if origMask[0] == '#' {
		mask, err = CasefoldChannel(origMask)
		isChannel = true
	} else if !strings.ContainsAny(origMask, protocolBreakingNameCharacters) {
		isBareNick = true
	} else {
		mask, err = CanonicalizeMaskWildcard(origMask)
	}

	if err != nil {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, client.Nick(), "WHO", client.t("Mask isn't valid"))
		return false
	}

	// include the r flag only if nick and account are synonymous
	config := server.Config()
	includeRFlag := config.Accounts.NickReservation.Enabled &&
		config.Accounts.NickReservation.Method == NickEnforcementStrict &&
		!config.Accounts.NickReservation.AllowCustomEnforcement &&
		config.Accounts.NickReservation.ForceNickEqualsAccount

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
	var fields whoxFields
	for _, field := range sFields {
		fields = fields.Add(field)
	}

	// successfully parsed query, ensure we send the success response:
	defer func() {
		rb.Add(nil, server.name, RPL_ENDOFWHO, client.Nick(), origMask, client.t("End of WHO list"))
	}()

	// XXX #1730: https://datatracker.ietf.org/doc/html/rfc1459#section-4.5.1
	// 'If the "o" parameter is passed only operators are returned according to
	// the name mask supplied.'
	// see discussion on #1730, we just return no results in this case.
	if len(msg.Params) > 1 && msg.Params[1] == "o" {
		return false
	}

	oper := client.Oper()
	hasPrivs := oper.HasRoleCapab("sajoin")
	canSeeIPs := oper.HasRoleCapab("ban")
	if isChannel {
		channel := server.channels.Get(mask)
		if channel != nil {
			isJoined := channel.hasClient(client)
			if !channel.flags.HasMode(modes.Secret) || isJoined || hasPrivs {
				var members []*Client
				if hasPrivs {
					members = channel.Members()
				} else {
					members = channel.auditoriumFriends(client)
				}
				for _, member := range members {
					if !member.HasMode(modes.Invisible) || isJoined || hasPrivs {
						client.rplWhoReply(channel, member, rb, canSeeIPs, oper != nil, includeRFlag, isWhox, fields, whoType)
					}
				}
			}
		}
	} else if isBareNick {
		if mclient := server.clients.Get(mask); mclient != nil {
			client.rplWhoReply(nil, mclient, rb, canSeeIPs, oper != nil, includeRFlag, isWhox, fields, whoType)
		} else if service, ok := ErgoServices[strings.ToLower(mask)]; ok {
			serviceWhoReply(client, service, rb, isWhox, fields, whoType)
		}
	} else {
		// Construct set of channels the client is in.
		userChannels := make(ChannelSet)
		for _, channel := range client.Channels() {
			userChannels.Add(channel)
		}

		// Another client is a friend if they share at least one channel, or they are the same client.
		isFriend := func(otherClient *Client) bool {
			if client == otherClient {
				return true
			}

			for _, channel := range otherClient.Channels() {
				if channel.flags.HasMode(modes.Auditorium) {
					return false // TODO this should respect +v etc.
				}
				if userChannels.Has(channel) {
					return true
				}
			}
			return false
		}

		for mclient := range server.clients.FindAll(mask) {
			if hasPrivs || !mclient.HasMode(modes.Invisible) || isFriend(mclient) {
				client.rplWhoReply(nil, mclient, rb, canSeeIPs, oper != nil, includeRFlag, isWhox, fields, whoType)
			}
		}
	}

	return false
}

// WHOIS [<target>] <mask>{,<mask>}
func whoisHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
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
		service, ok := ErgoServices[cfnick]
		hostname := "localhost"
		config := server.Config()
		if config.Server.OverrideServicesHostname != "" {
			hostname = config.Server.OverrideServicesHostname
		}
		if !ok {
			return false
		}
		clientNick := client.Nick()
		rb.Add(nil, client.server.name, RPL_WHOISUSER, clientNick, service.Name, service.Name, hostname, "*", service.Realname(client))
		// #1080:
		rb.Add(nil, client.server.name, RPL_WHOISOPERATOR, clientNick, service.Name, client.t("is a network service"))
		// hehe
		if client.HasMode(modes.TLS) {
			rb.Add(nil, client.server.name, RPL_WHOISSECURE, clientNick, service.Name, client.t("is using a secure connection"))
		}
		return true
	}

	hasPrivs := client.HasRoleCapabs("samode")
	if hasPrivs {
		for _, mask := range strings.Split(masksString, ",") {
			matches := server.clients.FindAll(mask)
			if len(matches) == 0 && !handleService(mask) {
				rb.Add(nil, client.server.name, ERR_NOSUCHNICK, client.Nick(), utils.SafeErrorParam(mask), client.t("No such nick"))
				continue
			}
			for mclient := range matches {
				client.getWhoisOf(mclient, hasPrivs, rb)
			}
		}
	} else {
		// only get the first request; also require a nick, not a mask
		nick := strings.Split(masksString, ",")[0]
		mclient := server.clients.Get(nick)
		if mclient != nil {
			client.getWhoisOf(mclient, hasPrivs, rb)
		} else if !handleService(nick) {
			rb.Add(nil, client.server.name, ERR_NOSUCHNICK, client.Nick(), utils.SafeErrorParam(masksString), client.t("No such nick"))
		}
		// fall through, ENDOFWHOIS is always sent
	}
	rb.Add(nil, server.name, RPL_ENDOFWHOIS, client.nick, utils.SafeErrorParam(masksString), client.t("End of /WHOIS list"))
	return false
}

// WHOWAS <nickname> [<count> [<server>]]
func whowasHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	nicknames := strings.Split(msg.Params[0], ",")

	// 0 means "all the entries", as does a negative number
	var count int
	if len(msg.Params) > 1 {
		count, _ = strconv.Atoi(msg.Params[1])
		if count < 0 {
			count = 0
		}
	}
	cnick := client.Nick()
	canSeeIP := client.Oper().HasRoleCapab("ban")
	for _, nickname := range nicknames {
		results := server.whoWas.Find(nickname, count)
		if len(results) == 0 {
			rb.Add(nil, server.name, ERR_WASNOSUCHNICK, cnick, utils.SafeErrorParam(nickname), client.t("There was no such nickname"))
		} else {
			for _, whoWas := range results {
				rb.Add(nil, server.name, RPL_WHOWASUSER, cnick, whoWas.nick, whoWas.username, whoWas.hostname, "*", whoWas.realname)
				if canSeeIP {
					rb.Add(nil, server.name, RPL_WHOWASIP, cnick, whoWas.nick, fmt.Sprintf(client.t("was connecting from %s"), utils.IPStringToHostname(whoWas.ip.String())))
				}
			}
		}
		rb.Add(nil, server.name, RPL_ENDOFWHOWAS, cnick, utils.SafeErrorParam(nickname), client.t("End of WHOWAS"))
	}
	return false
}

// ZNC <module> [params]
func zncHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	params := msg.Params[1:]
	// #1205: compatibility with Palaver, which sends `ZNC *playback :play ...`
	if len(params) == 1 && strings.IndexByte(params[0], ' ') != -1 {
		params = strings.Fields(params[0])
	}
	zncModuleHandler(client, msg.Params[0], params, rb)
	return false
}

// fake handler for unknown commands
func unknownCommandHandler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	var message string
	if strings.HasPrefix(msg.Command, "/") {
		message = fmt.Sprintf(client.t("Unknown command; if you are using /QUOTE, the correct syntax is /QUOTE %[1]s, not /QUOTE %[2]s"),
			strings.TrimPrefix(msg.Command, "/"), msg.Command)
	} else {
		message = client.t("Unknown command")
	}

	rb.Add(nil, server.name, ERR_UNKNOWNCOMMAND, client.Nick(), utils.SafeErrorParam(msg.Command), message)
	return false
}

// fake handler for invalid utf8
func invalidUtf8Handler(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool {
	rb.Add(nil, server.name, "FAIL", utils.SafeErrorParam(msg.Command), "INVALID_UTF8", client.t("Message rejected for containing invalid UTF-8"))
	return false
}
