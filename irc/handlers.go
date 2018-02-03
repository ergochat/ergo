// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2018 Daniel Oaks <daniel@danieloaks.net>
// Copyright (c) 2017-2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
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
	"github.com/goshuirc/irc-go/ircmatch"
	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/oragono/oragono/irc/caps"
	"github.com/oragono/oragono/irc/custime"
	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/passwd"
	"github.com/oragono/oragono/irc/sno"
	"github.com/oragono/oragono/irc/utils"
	"github.com/tidwall/buntdb"
)

// accHandler parses the ACC command.
func accHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	subcommand := strings.ToLower(msg.Params[0])

	if subcommand == "register" {
		return accRegisterHandler(server, client, msg)
	} else if subcommand == "verify" {
		client.Notice(client.t("VERIFY is not yet implemented"))
	} else {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, "ACC", msg.Params[0], client.t("Unknown subcommand"))
	}

	return false
}

// accRegisterHandler parses the ACC REGISTER command.
func accRegisterHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// make sure reg is enabled
	if !server.accountRegistration.Enabled {
		client.Send(nil, server.name, ERR_REG_UNSPECIFIED_ERROR, client.nick, "*", client.t("Account registration is disabled"))
		return false
	}

	// clients can't reg new accounts if they're already logged in
	if client.LoggedIntoAccount() {
		if server.accountRegistration.AllowMultiplePerConnection {
			client.LogoutOfAccount()
		} else {
			client.Send(nil, server.name, ERR_REG_UNSPECIFIED_ERROR, client.nick, "*", client.t("You're already logged into an account"))
			return false
		}
	}

	// get and sanitise account name
	account := strings.TrimSpace(msg.Params[1])
	casefoldedAccount, err := CasefoldName(account)
	// probably don't need explicit check for "*" here... but let's do it anyway just to make sure
	if err != nil || msg.Params[1] == "*" {
		client.Send(nil, server.name, ERR_REG_UNSPECIFIED_ERROR, client.nick, account, client.t("Account name is not valid"))
		return false
	}

	// check whether account exists
	// do it all in one write tx to prevent races
	err = server.store.Update(func(tx *buntdb.Tx) error {
		accountKey := fmt.Sprintf(keyAccountExists, casefoldedAccount)

		_, err := tx.Get(accountKey)
		if err != buntdb.ErrNotFound {
			//TODO(dan): if account verified key doesn't exist account is not verified, calc the maximum time without verification and expire and continue if need be
			client.Send(nil, server.name, ERR_ACCOUNT_ALREADY_EXISTS, client.nick, account, client.t("Account already exists"))
			return errAccountCreation
		}

		registeredTimeKey := fmt.Sprintf(keyAccountRegTime, casefoldedAccount)

		tx.Set(accountKey, "1", nil)
		tx.Set(fmt.Sprintf(keyAccountName, casefoldedAccount), account, nil)
		tx.Set(registeredTimeKey, strconv.FormatInt(time.Now().Unix(), 10), nil)
		return nil
	})

	// account could not be created and relevant numerics have been dispatched, abort
	if err != nil {
		if err != errAccountCreation {
			client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, "ACC", "REGISTER", client.t("Could not register"))
			log.Println("Could not save registration initial data:", err.Error())
		}
		return false
	}

	// account didn't already exist, continue with account creation and dispatching verification (if required)
	callback := strings.ToLower(msg.Params[2])
	var callbackNamespace, callbackValue string

	if callback == "*" {
		callbackNamespace = "*"
	} else if strings.Contains(callback, ":") {
		callbackValues := strings.SplitN(callback, ":", 2)
		callbackNamespace, callbackValue = callbackValues[0], callbackValues[1]
	} else {
		callbackNamespace = server.accountRegistration.EnabledCallbacks[0]
		callbackValue = callback
	}

	// ensure the callback namespace is valid
	// need to search callback list, maybe look at using a map later?
	var callbackValid bool
	for _, name := range server.accountRegistration.EnabledCallbacks {
		if callbackNamespace == name {
			callbackValid = true
		}
	}

	if !callbackValid {
		client.Send(nil, server.name, ERR_REG_INVALID_CALLBACK, client.nick, account, callbackNamespace, client.t("Callback namespace is not supported"))
		removeFailedAccRegisterData(server.store, casefoldedAccount)
		return false
	}

	// get credential type/value
	var credentialType, credentialValue string

	if len(msg.Params) > 4 {
		credentialType = strings.ToLower(msg.Params[3])
		credentialValue = msg.Params[4]
	} else if len(msg.Params) == 4 {
		credentialType = "passphrase" // default from the spec
		credentialValue = msg.Params[3]
	} else {
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, msg.Command, client.t("Not enough parameters"))
		removeFailedAccRegisterData(server.store, casefoldedAccount)
		return false
	}

	// ensure the credential type is valid
	var credentialValid bool
	for _, name := range server.accountRegistration.EnabledCredentialTypes {
		if credentialType == name {
			credentialValid = true
		}
	}
	if credentialType == "certfp" && client.certfp == "" {
		client.Send(nil, server.name, ERR_REG_INVALID_CRED_TYPE, client.nick, credentialType, callbackNamespace, client.t("You are not using a TLS certificate"))
		removeFailedAccRegisterData(server.store, casefoldedAccount)
		return false
	}

	if !credentialValid {
		client.Send(nil, server.name, ERR_REG_INVALID_CRED_TYPE, client.nick, credentialType, callbackNamespace, client.t("Credential type is not supported"))
		removeFailedAccRegisterData(server.store, casefoldedAccount)
		return false
	}

	// store details
	err = server.store.Update(func(tx *buntdb.Tx) error {
		// certfp special lookup key
		if credentialType == "certfp" {
			assembledKeyCertToAccount := fmt.Sprintf(keyCertToAccount, client.certfp)

			// make sure certfp doesn't already exist because that'd be silly
			_, err := tx.Get(assembledKeyCertToAccount)
			if err != buntdb.ErrNotFound {
				return errCertfpAlreadyExists
			}

			tx.Set(assembledKeyCertToAccount, casefoldedAccount, nil)
		}

		// make creds
		var creds AccountCredentials

		// always set passphrase salt
		creds.PassphraseSalt, err = passwd.NewSalt()
		if err != nil {
			return fmt.Errorf("Could not create passphrase salt: %s", err.Error())
		}

		if credentialType == "certfp" {
			creds.Certificate = client.certfp
		} else if credentialType == "passphrase" {
			creds.PassphraseHash, err = server.passwords.GenerateFromPassword(creds.PassphraseSalt, credentialValue)
			if err != nil {
				return fmt.Errorf("Could not hash password: %s", err)
			}
		}
		credText, err := json.Marshal(creds)
		if err != nil {
			return fmt.Errorf("Could not marshal creds: %s", err)
		}
		tx.Set(fmt.Sprintf(keyAccountCredentials, account), string(credText), nil)

		return nil
	})

	// details could not be stored and relevant numerics have been dispatched, abort
	if err != nil {
		errMsg := "Could not register"
		if err == errCertfpAlreadyExists {
			errMsg = "An account already exists for your certificate fingerprint"
		}
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, "ACC", "REGISTER", errMsg)
		log.Println("Could not save registration creds:", err.Error())
		removeFailedAccRegisterData(server.store, casefoldedAccount)
		return false
	}

	// automatically complete registration
	if callbackNamespace == "*" {
		err = server.store.Update(func(tx *buntdb.Tx) error {
			tx.Set(fmt.Sprintf(keyAccountVerified, casefoldedAccount), "1", nil)

			// load acct info inside store tx
			account := ClientAccount{
				Name:         strings.TrimSpace(msg.Params[1]),
				RegisteredAt: time.Now(),
				Clients:      []*Client{client},
			}
			//TODO(dan): Consider creating ircd-wide account adding/removing/affecting lock for protecting access to these sorts of variables
			server.accounts[casefoldedAccount] = &account
			client.account = &account

			client.Send(nil, server.name, RPL_REGISTRATION_SUCCESS, client.nick, account.Name, client.t("Account created"))
			client.Send(nil, server.name, RPL_LOGGEDIN, client.nick, client.nickMaskString, account.Name, fmt.Sprintf(client.t("You are now logged in as %s"), account.Name))
			client.Send(nil, server.name, RPL_SASLSUCCESS, client.nick, client.t("Authentication successful"))
			server.snomasks.Send(sno.LocalAccounts, fmt.Sprintf(ircfmt.Unescape("Account registered $c[grey][$r%s$c[grey]] by $c[grey][$r%s$c[grey]]"), account.Name, client.nickMaskString))
			return nil
		})
		if err != nil {
			client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, "ACC", "REGISTER", client.t("Could not register"))
			log.Println("Could not save verification confirmation (*):", err.Error())
			removeFailedAccRegisterData(server.store, casefoldedAccount)
			return false
		}

		return false
	}

	// dispatch callback
	client.Notice(fmt.Sprintf("We should dispatch a real callback here to %s:%s", callbackNamespace, callbackValue))

	return false
}

// authenticateHandler parses the AUTHENTICATE command (for SASL authentication).
func authenticateHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// sasl abort
	if !server.accountAuthenticationEnabled || len(msg.Params) == 1 && msg.Params[0] == "*" {
		client.Send(nil, server.name, ERR_SASLABORTED, client.nick, client.t("SASL authentication aborted"))
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
			client.Send(nil, server.name, ERR_SASLFAIL, client.nick, client.t("SASL authentication failed"))
		}

		return false
	}

	// continue existing sasl session
	rawData := msg.Params[0]

	if len(rawData) > 400 {
		client.Send(nil, server.name, ERR_SASLTOOLONG, client.nick, client.t("SASL message too long"))
		client.saslInProgress = false
		client.saslMechanism = ""
		client.saslValue = ""
		return false
	} else if len(rawData) == 400 {
		client.saslValue += rawData
		// allow 4 'continuation' lines before rejecting for length
		if len(client.saslValue) > 400*4 {
			client.Send(nil, server.name, ERR_SASLFAIL, client.nick, client.t("SASL authentication failed: Passphrase too long"))
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
			client.Send(nil, server.name, ERR_SASLFAIL, client.nick, client.t("SASL authentication failed: Invalid b64 encoding"))
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
		client.Send(nil, server.name, ERR_SASLFAIL, client.nick, client.t("SASL authentication failed"))
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
			client.Send(nil, server.name, ERR_SASLFAIL, client.nick, client.t("SASL authentication failed: authcid and authzid should be the same"))
			return false
		}
	} else {
		client.Send(nil, server.name, ERR_SASLFAIL, client.nick, client.t("SASL authentication failed: Invalid auth blob"))
		return false
	}

	// keep it the same as in the REG CREATE stage
	accountKey, err := CasefoldName(accountKey)
	if err != nil {
		client.Send(nil, server.name, ERR_SASLFAIL, client.nick, client.t("SASL authentication failed: Bad account name"))
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
		client.Send(nil, server.name, ERR_SASLFAIL, client.nick, client.t("SASL authentication failed"))
		return false
	}

	client.successfulSaslAuth()
	return false
}

// authExternalHandler parses the SASL EXTERNAL mechanism.
func authExternalHandler(server *Server, client *Client, mechanism string, value []byte) bool {
	if client.certfp == "" {
		client.Send(nil, server.name, ERR_SASLFAIL, client.nick, client.t("SASL authentication failed, you are not connecting with a certificate"))
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
		client.Send(nil, server.name, ERR_SASLFAIL, client.nick, client.t("SASL authentication failed"))
		return false
	}

	client.successfulSaslAuth()
	return false
}

// AWAY [<message>]
func awayHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var isAway bool
	var text string
	if len(msg.Params) > 0 {
		isAway = true
		text = msg.Params[0]
		awayLen := server.Limits().AwayLen
		if len(text) > awayLen {
			text = text[:awayLen]
		}
	}

	if isAway {
		client.flags[modes.Away] = true
	} else {
		delete(client.flags, modes.Away)
	}
	client.awayMessage = text

	var op modes.ModeOp
	if client.flags[modes.Away] {
		op = modes.Add
		client.Send(nil, server.name, RPL_NOWAWAY, client.nick, client.t("You have been marked as being away"))
	} else {
		op = modes.Remove
		client.Send(nil, server.name, RPL_UNAWAY, client.nick, client.t("You are no longer marked as being away"))
	}
	//TODO(dan): Should this be sent automagically as part of setting the flag/mode?
	modech := modes.ModeChanges{modes.ModeChange{
		Mode: modes.Away,
		Op:   op,
	}}
	client.Send(nil, server.name, "MODE", client.nick, modech.String())

	// dispatch away-notify
	for friend := range client.Friends(caps.AwayNotify) {
		if client.flags[modes.Away] {
			friend.SendFromClient("", client, nil, "AWAY", client.awayMessage)
		} else {
			friend.SendFromClient("", client, nil, "AWAY")
		}
	}

	return false
}

// CAP <subcmd> [<caps>]
func capHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	subCommand := strings.ToUpper(msg.Params[0])
	capabilities := caps.NewSet()
	var capString string

	if len(msg.Params) > 1 {
		capString = msg.Params[1]
		strs := strings.Split(capString, " ")
		for _, str := range strs {
			if len(str) > 0 {
				capabilities.Enable(caps.Capability(str))
			}
		}
	}

	switch subCommand {
	case "LS":
		if !client.registered {
			client.capState = CapNegotiating
		}
		if len(msg.Params) > 1 && msg.Params[1] == "302" {
			client.capVersion = 302
		}
		// weechat 1.4 has a bug here where it won't accept the CAP reply unless it contains
		// the server.name source... otherwise it doesn't respond to the CAP message with
		// anything and just hangs on connection.
		//TODO(dan): limit number of caps and send it multiline in 3.2 style as appropriate.
		client.Send(nil, server.name, "CAP", client.nick, subCommand, SupportedCapabilities.String(client.capVersion, CapValues))

	case "LIST":
		client.Send(nil, server.name, "CAP", client.nick, subCommand, client.capabilities.String(caps.Cap301, CapValues)) // values not sent on LIST so force 3.1

	case "REQ":
		if !client.registered {
			client.capState = CapNegotiating
		}

		// make sure all capabilities actually exist
		for _, capability := range capabilities.List() {
			if !SupportedCapabilities.Has(capability) {
				client.Send(nil, server.name, "CAP", client.nick, "NAK", capString)
				return false
			}
		}
		client.capabilities.Enable(capabilities.List()...)
		client.Send(nil, server.name, "CAP", client.nick, "ACK", capString)

	case "END":
		if !client.registered {
			client.capState = CapNegotiated
			server.tryRegister(client)
		}

	default:
		client.Send(nil, server.name, ERR_INVALIDCAPCMD, client.nick, subCommand, client.t("Invalid CAP subcommand"))
	}
	return false
}

// csHandler handles the /CS and /CHANSERV commands
func csHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	server.chanservReceivePrivmsg(client, strings.Join(msg.Params, " "))
	return false
}

// DEBUG GCSTATS/NUMGOROUTINE/etc
func debugHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if !client.flags[modes.Operator] {
		return false
	}

	switch msg.Params[0] {
	case "GCSTATS":
		stats := debug.GCStats{
			Pause:          make([]time.Duration, 10),
			PauseQuantiles: make([]time.Duration, 5),
		}
		debug.ReadGCStats(&stats)

		client.Notice(fmt.Sprintf("last GC:     %s", stats.LastGC.Format(time.RFC1123)))
		client.Notice(fmt.Sprintf("num GC:      %d", stats.NumGC))
		client.Notice(fmt.Sprintf("pause total: %s", stats.PauseTotal))
		client.Notice(fmt.Sprintf("pause quantiles min%%: %s", stats.PauseQuantiles[0]))
		client.Notice(fmt.Sprintf("pause quantiles 25%%:  %s", stats.PauseQuantiles[1]))
		client.Notice(fmt.Sprintf("pause quantiles 50%%:  %s", stats.PauseQuantiles[2]))
		client.Notice(fmt.Sprintf("pause quantiles 75%%:  %s", stats.PauseQuantiles[3]))
		client.Notice(fmt.Sprintf("pause quantiles max%%: %s", stats.PauseQuantiles[4]))

	case "NUMGOROUTINE":
		count := runtime.NumGoroutine()
		client.Notice(fmt.Sprintf("num goroutines: %d", count))

	case "PROFILEHEAP":
		profFile := "oragono.mprof"
		file, err := os.Create(profFile)
		if err != nil {
			client.Notice(fmt.Sprintf("error: %s", err))
			break
		}
		defer file.Close()
		pprof.Lookup("heap").WriteTo(file, 0)
		client.Notice(fmt.Sprintf("written to %s", profFile))

	case "STARTCPUPROFILE":
		profFile := "oragono.prof"
		file, err := os.Create(profFile)
		if err != nil {
			client.Notice(fmt.Sprintf("error: %s", err))
			break
		}
		if err := pprof.StartCPUProfile(file); err != nil {
			defer file.Close()
			client.Notice(fmt.Sprintf("error: %s", err))
			break
		}

		client.Notice(fmt.Sprintf("CPU profile writing to %s", profFile))

	case "STOPCPUPROFILE":
		pprof.StopCPUProfile()
		client.Notice(fmt.Sprintf("CPU profiling stopped"))
	}
	return false
}

// DLINE [ANDKILL] [MYSELF] [duration] <ip>/<net> [ON <server>] [reason [| oper reason]]
// DLINE LIST
func dlineHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// check oper permissions
	if !client.class.Capabilities["oper:local_ban"] {
		client.Send(nil, server.name, ERR_NOPRIVS, client.nick, msg.Command, client.t("Insufficient oper privs"))
		return false
	}

	currentArg := 0

	// if they say LIST, we just list the current dlines
	if len(msg.Params) == currentArg+1 && strings.ToLower(msg.Params[currentArg]) == "list" {
		bans := server.dlines.AllBans()

		if len(bans) == 0 {
			client.Notice(client.t("No DLINEs have been set!"))
		}

		for key, info := range bans {
			client.Notice(fmt.Sprintf(client.t("Ban - %[1]s - added by %[2]s - %[3]s"), key, info.OperName, info.BanMessage("%s")))
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
	durationIsUsed := err == nil
	if durationIsUsed {
		currentArg++
	}

	// get host
	if len(msg.Params) < currentArg+1 {
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, msg.Command, client.t("Not enough parameters"))
		return false
	}
	hostString := msg.Params[currentArg]
	currentArg++

	// check host
	var hostAddr net.IP
	var hostNet *net.IPNet

	_, hostNet, err = net.ParseCIDR(hostString)
	if err != nil {
		hostAddr = net.ParseIP(hostString)
	}

	if hostAddr == nil && hostNet == nil {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("Could not parse IP address or CIDR network"))
		return false
	}

	if hostNet == nil {
		hostString = hostAddr.String()
		if !dlineMyself && hostAddr.Equal(client.IP()) {
			client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("This ban matches you. To DLINE yourself, you must use the command:  /DLINE MYSELF <arguments>"))
			return false
		}
	} else {
		hostString = hostNet.String()
		if !dlineMyself && hostNet.Contains(client.IP()) {
			client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("This ban matches you. To DLINE yourself, you must use the command:  /DLINE MYSELF <arguments>"))
			return false
		}
	}

	// check remote
	if len(msg.Params) > currentArg && msg.Params[currentArg] == "ON" {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("Remote servers not yet supported"))
		return false
	}

	// get comment(s)
	reason := "No reason given"
	operReason := "No reason given"
	if len(msg.Params) > currentArg {
		tempReason := strings.TrimSpace(msg.Params[currentArg])
		if len(tempReason) > 0 && tempReason != "|" {
			tempReasons := strings.SplitN(tempReason, "|", 2)
			if tempReasons[0] != "" {
				reason = tempReasons[0]
			}
			if len(tempReasons) > 1 && tempReasons[1] != "" {
				operReason = tempReasons[1]
			} else {
				operReason = reason
			}
		}
	}
	operName := client.operName
	if operName == "" {
		operName = server.name
	}

	// assemble ban info
	var banTime *IPRestrictTime
	if durationIsUsed {
		banTime = &IPRestrictTime{
			Duration: duration,
			Expires:  time.Now().Add(duration),
		}
	}

	info := IPBanInfo{
		Reason:     reason,
		OperReason: operReason,
		OperName:   operName,
		Time:       banTime,
	}

	// save in datastore
	err = server.store.Update(func(tx *buntdb.Tx) error {
		dlineKey := fmt.Sprintf(keyDlineEntry, hostString)

		// assemble json from ban info
		b, err := json.Marshal(info)
		if err != nil {
			return err
		}

		tx.Set(dlineKey, string(b), nil)

		return nil
	})

	if err != nil {
		client.Notice(fmt.Sprintf(client.t("Could not successfully save new D-LINE: %s"), err.Error()))
		return false
	}

	if hostNet == nil {
		server.dlines.AddIP(hostAddr, banTime, reason, operReason, operName)
	} else {
		server.dlines.AddNetwork(*hostNet, banTime, reason, operReason, operName)
	}

	var snoDescription string
	if durationIsUsed {
		client.Notice(fmt.Sprintf(client.t("Added temporary (%[1]s) D-Line for %[2]s"), duration.String(), hostString))
		snoDescription = fmt.Sprintf(ircfmt.Unescape("%s [%s]$r added temporary (%s) D-Line for %s"), client.nick, operName, duration.String(), hostString)
	} else {
		client.Notice(fmt.Sprintf(client.t("Added D-Line for %s"), hostString))
		snoDescription = fmt.Sprintf(ircfmt.Unescape("%s [%s]$r added D-Line for %s"), client.nick, operName, hostString)
	}
	server.snomasks.Send(sno.LocalXline, snoDescription)

	var killClient bool
	if andKill {
		var clientsToKill []*Client
		var killedClientNicks []string
		var toKill bool

		for _, mcl := range server.clients.AllClients() {
			if hostNet == nil {
				toKill = hostAddr.Equal(mcl.IP())
			} else {
				toKill = hostNet.Contains(mcl.IP())
			}

			if toKill {
				clientsToKill = append(clientsToKill, mcl)
				killedClientNicks = append(killedClientNicks, mcl.nick)
			}
		}

		for _, mcl := range clientsToKill {
			mcl.exitedSnomaskSent = true
			mcl.Quit(fmt.Sprintf(mcl.t("You have been banned from this server (%s)"), reason))
			if mcl == client {
				killClient = true
			} else {
				// if mcl == client, we kill them below
				mcl.destroy(false)
			}
		}

		// send snomask
		sort.Strings(killedClientNicks)
		server.snomasks.Send(sno.LocalKills, fmt.Sprintf(ircfmt.Unescape("%s [%s] killed %d clients with a DLINE $c[grey][$r%s$c[grey]]"), client.nick, operName, len(killedClientNicks), strings.Join(killedClientNicks, ", ")))
	}

	return killClient
}

// helpHandler returns the appropriate help for the given query.
func helpHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	argument := strings.ToLower(strings.TrimSpace(strings.Join(msg.Params, " ")))

	if len(argument) < 1 {
		client.sendHelp("HELPOP", client.t(`HELPOP <argument>

Get an explanation of <argument>, or "index" for a list of help topics.`))
		return false
	}

	// handle index
	if argument == "index" {
		if client.flags[modes.Operator] {
			client.sendHelp("HELP", GetHelpIndex(client.languages, HelpIndexOpers))
		} else {
			client.sendHelp("HELP", GetHelpIndex(client.languages, HelpIndex))
		}
		return false
	}

	helpHandler, exists := Help[argument]

	if exists && (!helpHandler.oper || (helpHandler.oper && client.flags[modes.Operator])) {
		if helpHandler.textGenerator != nil {
			client.sendHelp(strings.ToUpper(argument), client.t(helpHandler.textGenerator(client)))
		} else {
			client.sendHelp(strings.ToUpper(argument), client.t(helpHandler.text))
		}
	} else {
		args := msg.Params
		args = append(args, client.t("Help not found"))
		client.Send(nil, server.name, ERR_HELPNOTFOUND, args...)
	}

	return false
}

// INFO
func infoHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// we do the below so that the human-readable lines in info can be translated.
	for _, line := range infoString1 {
		client.Send(nil, server.name, RPL_INFO, client.nick, line)
	}
	client.Send(nil, server.name, RPL_INFO, client.nick, client.t("Oragono is released under the MIT license."))
	client.Send(nil, server.name, RPL_INFO, client.nick, "")
	client.Send(nil, server.name, RPL_INFO, client.nick, client.t("Thanks to Jeremy Latt for founding Ergonomadic, the project this is based on")+" <3")
	client.Send(nil, server.name, RPL_INFO, client.nick, "")
	client.Send(nil, server.name, RPL_INFO, client.nick, client.t("Core Developers:"))
	for _, line := range infoString2 {
		client.Send(nil, server.name, RPL_INFO, client.nick, line)
	}
	client.Send(nil, server.name, RPL_INFO, client.nick, client.t("Contributors and Former Developers:"))
	for _, line := range infoString3 {
		client.Send(nil, server.name, RPL_INFO, client.nick, line)
	}
	// show translators for languages other than good ole' regular English
	tlines := server.languages.Translators()
	if 0 < len(tlines) {
		client.Send(nil, server.name, RPL_INFO, client.nick, client.t("Translators:"))
		for _, line := range tlines {
			client.Send(nil, server.name, RPL_INFO, client.nick, "    "+line)
		}
		client.Send(nil, server.name, RPL_INFO, client.nick, "")
	}
	client.Send(nil, server.name, RPL_ENDOFINFO, client.nick, client.t("End of /INFO"))
	return false
}

// INVITE <nickname> <channel>
func inviteHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	nickname := msg.Params[0]
	channelName := msg.Params[1]

	casefoldedNickname, err := CasefoldName(nickname)
	target := server.clients.Get(casefoldedNickname)
	if err != nil || target == nil {
		client.Send(nil, server.name, ERR_NOSUCHNICK, client.nick, nickname, client.t("No such nick"))
		return false
	}

	casefoldedChannelName, err := CasefoldChannel(channelName)
	channel := server.channels.Get(casefoldedChannelName)
	if err != nil || channel == nil {
		client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, channelName, client.t("No such channel"))
		return false
	}

	channel.Invite(target, client)
	return false
}

// ISON <nick>{ <nick>}
func isonHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var nicks = msg.Params

	var err error
	var casefoldedNick string
	ison := make([]string, 0)
	for _, nick := range nicks {
		casefoldedNick, err = CasefoldName(nick)
		if err != nil {
			continue
		}
		if iclient := server.clients.Get(casefoldedNick); iclient != nil {
			ison = append(ison, iclient.nick)
		}
	}

	client.Send(nil, server.name, RPL_ISON, client.nick, strings.Join(nicks, " "))
	return false
}

// JOIN <channel>{,<channel>} [<key>{,<key>}]
func joinHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// kill JOIN 0 requests
	if msg.Params[0] == "0" {
		client.Notice(client.t("JOIN 0 is not allowed"))
		return false
	}

	// handle regular JOINs
	channels := strings.Split(msg.Params[0], ",")
	var keys []string
	if len(msg.Params) > 1 {
		keys = strings.Split(msg.Params[1], ",")
	}

	for i, name := range channels {
		var key string
		if len(keys) > i {
			key = keys[i]
		}
		err := server.channels.Join(client, name, key)
		if err == NoSuchChannel {
			client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.Nick(), name, client.t("No such channel"))
		}
	}
	return false
}

// KICK <channel>{,<channel>} <user>{,<user>} [<comment>]
func kickHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	channels := strings.Split(msg.Params[0], ",")
	users := strings.Split(msg.Params[1], ",")
	if (len(channels) != len(users)) && (len(users) != 1) {
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, "KICK", client.t("Not enough parameters"))
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
			client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, chname, client.t("No such channel"))
			continue
		}

		casefoldedNickname, err := CasefoldName(nickname)
		target := server.clients.Get(casefoldedNickname)
		if err != nil || target == nil {
			client.Send(nil, server.name, ERR_NOSUCHNICK, client.nick, nickname, client.t("No such nick"))
			continue
		}

		if comment == "" {
			comment = nickname
		}
		channel.Kick(client, target, comment)
	}
	return false
}

// KILL <nickname> <comment>
func killHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	nickname := msg.Params[0]
	comment := "<no reason supplied>"
	if len(msg.Params) > 1 {
		comment = msg.Params[1]
	}

	casefoldedNickname, err := CasefoldName(nickname)
	target := server.clients.Get(casefoldedNickname)
	if err != nil || target == nil {
		client.Send(nil, client.server.name, ERR_NOSUCHNICK, client.nick, nickname, client.t("No such nick"))
		return false
	}

	quitMsg := fmt.Sprintf("Killed (%s (%s))", client.nick, comment)

	server.snomasks.Send(sno.LocalKills, fmt.Sprintf(ircfmt.Unescape("%s$r was killed by %s $c[grey][$r%s$c[grey]]"), target.nick, client.nick, comment))
	target.exitedSnomaskSent = true

	target.Quit(quitMsg)
	target.destroy(false)
	return false
}

// KLINE [ANDKILL] [MYSELF] [duration] <mask> [ON <server>] [reason [| oper reason]]
// KLINE LIST
func klineHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// check oper permissions
	if !client.class.Capabilities["oper:local_ban"] {
		client.Send(nil, server.name, ERR_NOPRIVS, client.nick, msg.Command, client.t("Insufficient oper privs"))
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
			client.Notice(fmt.Sprintf(client.t("Ban - %s - added by %s - %s"), key, info.OperName, info.BanMessage("%s")))
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
	durationIsUsed := err == nil
	if durationIsUsed {
		currentArg++
	}

	// get mask
	if len(msg.Params) < currentArg+1 {
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, msg.Command, client.t("Not enough parameters"))
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
			client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("This ban matches you. To KLINE yourself, you must use the command:  /KLINE MYSELF <arguments>"))
			return false
		}
	}

	// check remote
	if len(msg.Params) > currentArg && msg.Params[currentArg] == "ON" {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("Remote servers not yet supported"))
		return false
	}

	// get oper name
	operName := client.operName
	if operName == "" {
		operName = server.name
	}

	// get comment(s)
	reason := "No reason given"
	operReason := "No reason given"
	if len(msg.Params) > currentArg {
		tempReason := strings.TrimSpace(msg.Params[currentArg])
		if len(tempReason) > 0 && tempReason != "|" {
			tempReasons := strings.SplitN(tempReason, "|", 2)
			if tempReasons[0] != "" {
				reason = tempReasons[0]
			}
			if len(tempReasons) > 1 && tempReasons[1] != "" {
				operReason = tempReasons[1]
			} else {
				operReason = reason
			}
		}
	}

	// assemble ban info
	var banTime *IPRestrictTime
	if durationIsUsed {
		banTime = &IPRestrictTime{
			Duration: duration,
			Expires:  time.Now().Add(duration),
		}
	}

	info := IPBanInfo{
		Reason:     reason,
		OperReason: operReason,
		OperName:   operName,
		Time:       banTime,
	}

	// save in datastore
	err = server.store.Update(func(tx *buntdb.Tx) error {
		klineKey := fmt.Sprintf(keyKlineEntry, mask)

		// assemble json from ban info
		b, err := json.Marshal(info)
		if err != nil {
			return err
		}

		tx.Set(klineKey, string(b), nil)

		return nil
	})

	if err != nil {
		client.Notice(fmt.Sprintf(client.t("Could not successfully save new K-LINE: %s"), err.Error()))
		return false
	}

	server.klines.AddMask(mask, banTime, reason, operReason, operName)

	var snoDescription string
	if durationIsUsed {
		client.Notice(fmt.Sprintf(client.t("Added temporary (%[1]s) K-Line for %[2]s"), duration.String(), mask))
		snoDescription = fmt.Sprintf(ircfmt.Unescape("%s [%s]$r added temporary (%s) K-Line for %s"), client.nick, operName, duration.String(), mask)
	} else {
		client.Notice(fmt.Sprintf(client.t("Added K-Line for %s"), mask))
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
			mcl.Quit(fmt.Sprintf(mcl.t("You have been banned from this server (%s)"), reason))
			if mcl == client {
				killClient = true
			} else {
				// if mcl == client, we kill them below
				mcl.destroy(false)
			}
		}

		// send snomask
		sort.Strings(killedClientNicks)
		server.snomasks.Send(sno.LocalKills, fmt.Sprintf(ircfmt.Unescape("%s [%s] killed %d clients with a KLINE $c[grey][$r%s$c[grey]]"), client.nick, operName, len(killedClientNicks), strings.Join(killedClientNicks, ", ")))
	}

	return killClient
}

// LANGUAGE <code>{ <code>}
func languageHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	alreadyDoneLanguages := make(map[string]bool)
	var appliedLanguages []string

	supportedLanguagesCount := server.languages.Count()
	if supportedLanguagesCount < len(msg.Params) {
		client.Send(nil, client.server.name, ERR_TOOMANYLANGUAGES, client.nick, strconv.Itoa(supportedLanguagesCount), client.t("You specified too many languages"))
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

		_, exists := server.languages.Info[value]
		if !exists {
			client.Send(nil, client.server.name, ERR_NOLANGUAGE, client.nick, client.t("Languages are not supported by this server"))
			return false
		}

		// if we've already applied the given language, skip it
		_, exists = alreadyDoneLanguages[value]
		if exists {
			continue
		}

		appliedLanguages = append(appliedLanguages, value)
	}

	client.stateMutex.Lock()
	if len(appliedLanguages) == 1 && appliedLanguages[0] == "en" {
		// premature optimisation ahoy!
		client.languages = []string{}
	} else {
		client.languages = appliedLanguages
	}
	client.stateMutex.Unlock()

	params := []string{client.nick}
	for _, lang := range appliedLanguages {
		params = append(params, lang)
	}
	params = append(params, client.t("Language preferences have been set"))

	client.Send(nil, client.server.name, RPL_YOURLANGUAGESARE, params...)

	return false
}

// LIST [<channel>{,<channel>}] [<elistcond>{,<elistcond>}]
func listHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
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

	if len(channels) == 0 {
		for _, channel := range server.channels.Channels() {
			if !client.flags[modes.Operator] && channel.flags[modes.Secret] {
				continue
			}
			if matcher.Matches(channel) {
				client.RplList(channel)
			}
		}
	} else {
		// limit regular users to only listing one channel
		if !client.flags[modes.Operator] {
			channels = channels[:1]
		}

		for _, chname := range channels {
			casefoldedChname, err := CasefoldChannel(chname)
			channel := server.channels.Get(casefoldedChname)
			if err != nil || channel == nil || (!client.flags[modes.Operator] && channel.flags[modes.Secret]) {
				if len(chname) > 0 {
					client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, chname, client.t("No such channel"))
				}
				continue
			}
			if matcher.Matches(channel) {
				client.RplList(channel)
			}
		}
	}
	client.Send(nil, server.name, RPL_LISTEND, client.nick, client.t("End of LIST"))
	return false
}

// LUSERS [<mask> [<server>]]
func lusersHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	//TODO(vegax87) Fix network statistics and additional parameters
	var totalcount, invisiblecount, opercount int

	for _, onlineusers := range server.clients.AllClients() {
		totalcount++
		if onlineusers.flags[modes.Invisible] {
			invisiblecount++
		}
		if onlineusers.flags[modes.Operator] {
			opercount++
		}
	}
	client.Send(nil, server.name, RPL_LUSERCLIENT, client.nick, fmt.Sprintf(client.t("There are %[1]d users and %[2]d invisible on %[3]d server(s)"), totalcount, invisiblecount, 1))
	client.Send(nil, server.name, RPL_LUSEROP, client.nick, fmt.Sprintf(client.t("%d IRC Operators online"), opercount))
	client.Send(nil, server.name, RPL_LUSERCHANNELS, client.nick, fmt.Sprintf(client.t("%d channels formed"), server.channels.Len()))
	client.Send(nil, server.name, RPL_LUSERME, client.nick, fmt.Sprintf(client.t("I have %[1]d clients and %[2]d servers"), totalcount, 1))
	return false
}

// MODE <target> [<modestring> [<mode arguments>...]]
func modeHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	_, errChan := CasefoldChannel(msg.Params[0])

	if errChan == nil {
		return cmodeHandler(server, client, msg)
	}
	return umodeHandler(server, client, msg)
}

// MODE <target> [<modestring> [<mode arguments>...]]
func cmodeHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	channelName, err := CasefoldChannel(msg.Params[0])
	channel := server.channels.Get(channelName)

	if err != nil || channel == nil {
		client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, msg.Params[0], client.t("No such channel"))
		return false
	}

	// applied mode changes
	applied := make(modes.ModeChanges, 0)

	if 1 < len(msg.Params) {
		// parse out real mode changes
		params := msg.Params[1:]
		changes, unknown := ParseChannelModeChanges(params...)

		// alert for unknown mode changes
		for char := range unknown {
			client.Send(nil, server.name, ERR_UNKNOWNMODE, client.nick, string(char), client.t("is an unknown mode character to me"))
		}
		if len(unknown) == 1 && len(changes) == 0 {
			return false
		}

		// apply mode changes
		applied = channel.ApplyChannelModeChanges(client, msg.Command == "SAMODE", changes)
	}

	// save changes to banlist/exceptlist/invexlist
	var banlistUpdated, exceptlistUpdated, invexlistUpdated bool
	for _, change := range applied {
		if change.Mode == modes.BanMask {
			banlistUpdated = true
		} else if change.Mode == modes.ExceptMask {
			exceptlistUpdated = true
		} else if change.Mode == modes.InviteMask {
			invexlistUpdated = true
		}
	}

	if (banlistUpdated || exceptlistUpdated || invexlistUpdated) && channel.IsRegistered() {
		go server.channelRegistry.StoreChannel(channel, true)
	}

	// send out changes
	if len(applied) > 0 {
		//TODO(dan): we should change the name of String and make it return a slice here
		args := append([]string{channel.name}, strings.Split(applied.String(), " ")...)
		for _, member := range channel.Members() {
			member.Send(nil, client.nickMaskString, "MODE", args...)
		}
	} else {
		args := append([]string{client.nick, channel.name}, channel.modeStrings(client)...)
		client.Send(nil, client.nickMaskString, RPL_CHANNELMODEIS, args...)
		client.Send(nil, client.nickMaskString, RPL_CHANNELCREATED, client.nick, channel.name, strconv.FormatInt(channel.createdTime.Unix(), 10))
	}
	return false
}

// MODE <target> [<modestring> [<mode arguments>...]]
func umodeHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	nickname, err := CasefoldName(msg.Params[0])
	target := server.clients.Get(nickname)
	if err != nil || target == nil {
		if len(msg.Params[0]) > 0 {
			client.Send(nil, server.name, ERR_NOSUCHNICK, client.nick, msg.Params[0], client.t("No such nick"))
		}
		return false
	}

	targetNick := target.Nick()
	hasPrivs := client == target || msg.Command == "SAMODE"

	if !hasPrivs {
		if len(msg.Params) > 1 {
			client.Send(nil, server.name, ERR_USERSDONTMATCH, client.nick, client.t("Can't change modes for other users"))
		} else {
			client.Send(nil, server.name, ERR_USERSDONTMATCH, client.nick, client.t("Can't view modes for other users"))
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
			client.Send(nil, server.name, ERR_UNKNOWNMODE, client.nick, string(char), client.t("is an unknown mode character to me"))
		}
		if len(unknown) == 1 && len(changes) == 0 {
			return false
		}

		// apply mode changes
		applied = target.applyUserModeChanges(msg.Command == "SAMODE", changes)
	}

	if len(applied) > 0 {
		client.Send(nil, client.nickMaskString, "MODE", targetNick, applied.String())
	} else if hasPrivs {
		client.Send(nil, target.nickMaskString, RPL_UMODEIS, targetNick, target.ModeString())
		if client.flags[modes.LocalOperator] || client.flags[modes.Operator] {
			masks := server.snomasks.String(client)
			if 0 < len(masks) {
				client.Send(nil, target.nickMaskString, RPL_SNOMASKIS, targetNick, masks, client.t("Server notice masks"))
			}
		}
	}
	return false
}

func monitorHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	handler, exists := metadataSubcommands[strings.ToLower(msg.Params[0])]

	if !exists {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.Nick(), "MONITOR", msg.Params[0], client.t("Unknown subcommand"))
		return false
	}

	return handler(server, client, msg)
}

func monitorRemoveHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if len(msg.Params) < 2 {
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.Nick(), msg.Command, client.t("Not enough parameters"))
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

func monitorAddHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if len(msg.Params) < 2 {
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.Nick(), msg.Command, client.t("Not enough parameters"))
		return false
	}

	var online []string
	var offline []string

	limit := server.Limits().MonitorEntries

	targets := strings.Split(msg.Params[1], ",")
	for _, target := range targets {
		// check name length
		if len(target) < 1 || len(targets) > server.limits.NickLen {
			continue
		}

		// add target
		casefoldedTarget, err := CasefoldName(target)
		if err != nil {
			continue
		}

		err = server.monitorManager.Add(client, casefoldedTarget, limit)
		if err == ErrMonitorLimitExceeded {
			client.Send(nil, server.name, ERR_MONLISTFULL, client.Nick(), strconv.Itoa(server.limits.MonitorEntries), strings.Join(targets, ","))
			break
		} else if err != nil {
			continue
		}

		// add to online / offline lists
		if targetClient := server.clients.Get(casefoldedTarget); targetClient == nil {
			offline = append(offline, target)
		} else {
			online = append(online, targetClient.Nick())
		}
	}

	if len(online) > 0 {
		client.Send(nil, server.name, RPL_MONONLINE, client.Nick(), strings.Join(online, ","))
	}
	if len(offline) > 0 {
		client.Send(nil, server.name, RPL_MONOFFLINE, client.Nick(), strings.Join(offline, ","))
	}

	return false
}

func monitorClearHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	server.monitorManager.RemoveAll(client)
	return false
}

func monitorListHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	monitorList := server.monitorManager.List(client)

	var nickList []string
	for _, cfnick := range monitorList {
		replynick := cfnick
		// report the uncasefolded nick if it's available, i.e., the client is online
		if mclient := server.clients.Get(cfnick); mclient != nil {
			replynick = mclient.Nick()
		}
		nickList = append(nickList, replynick)
	}

	for _, line := range utils.ArgsToStrings(maxLastArgLength, nickList, ",") {
		client.Send(nil, server.name, RPL_MONLIST, client.Nick(), line)
	}

	client.Send(nil, server.name, RPL_ENDOFMONLIST, "End of MONITOR list")

	return false
}

func monitorStatusHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var online []string
	var offline []string

	monitorList := server.monitorManager.List(client)

	for _, name := range monitorList {
		target := server.clients.Get(name)
		if target == nil {
			offline = append(offline, name)
		} else {
			online = append(online, target.Nick())
		}
	}

	if len(online) > 0 {
		for _, line := range utils.ArgsToStrings(maxLastArgLength, online, ",") {
			client.Send(nil, server.name, RPL_MONONLINE, client.Nick(), line)
		}
	}
	if len(offline) > 0 {
		for _, line := range utils.ArgsToStrings(maxLastArgLength, offline, ",") {
			client.Send(nil, server.name, RPL_MONOFFLINE, client.Nick(), line)
		}
	}

	return false
}

// MOTD [<target>]
func motdHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	//TODO(dan): hook this up when we have multiple servers I guess???
	//var target string
	//if len(msg.Params) > 0 {
	//	target = msg.Params[0]
	//}

	server.MOTD(client)
	return false
}

// NICK <nickname>
func nickHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if !client.authorized {
		client.Quit("Bad password")
		return true
	}

	return performNickChange(server, client, client, msg.Params[0])
}

// NOTICE <target>{,<target>} <message>
func noticeHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	clientOnlyTags := GetClientOnlyTags(msg.Tags)
	targets := strings.Split(msg.Params[0], ",")
	message := msg.Params[1]

	// split privmsg
	splitMsg := server.splitMessage(message, !client.capabilities.Has(caps.MaxLine))

	for i, targetString := range targets {
		// max of four targets per privmsg
		if i > maxTargets-1 {
			break
		}
		prefixes, targetString := modes.SplitChannelMembershipPrefixes(targetString)
		lowestPrefix := modes.GetLowestChannelModePrefix(prefixes)

		target, cerr := CasefoldChannel(targetString)
		if cerr == nil {
			channel := server.channels.Get(target)
			if channel == nil {
				// errors silently ignored with NOTICE as per RFC
				continue
			}
			if !channel.CanSpeak(client) {
				// errors silently ignored with NOTICE as per RFC
				continue
			}
			msgid := server.generateMessageID()
			channel.SplitNotice(msgid, lowestPrefix, clientOnlyTags, client, splitMsg)
		} else {
			target, err := CasefoldName(targetString)
			if err != nil {
				continue
			}
			if target == "chanserv" {
				server.chanservReceiveNotice(client, message)
				continue
			} else if target == "nickserv" {
				server.nickservReceiveNotice(client, message)
				continue
			}

			user := server.clients.Get(target)
			if user == nil {
				// errors silently ignored with NOTICE as per RFC
				continue
			}
			if !user.capabilities.Has(caps.MessageTags) {
				clientOnlyTags = nil
			}
			msgid := server.generateMessageID()
			// restrict messages appropriately when +R is set
			// intentionally make the sending user think the message went through fine
			if !user.flags[modes.RegisteredOnly] || client.registered {
				user.SendSplitMsgFromClient(msgid, client, clientOnlyTags, "NOTICE", user.nick, splitMsg)
			}
			if client.capabilities.Has(caps.EchoMessage) {
				client.SendSplitMsgFromClient(msgid, client, clientOnlyTags, "NOTICE", user.nick, splitMsg)
			}
		}
	}
	return false
}

// NPC <target> <sourcenick> <text to be sent>
func npcHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	target := msg.Params[0]
	fakeSource := msg.Params[1]
	message := msg.Params[2]

	_, err := CasefoldName(fakeSource)
	if err != nil {
		client.Send(nil, client.server.name, ERR_CANNOTSENDRP, target, client.t("Fake source must be a valid nickname"))
		return false
	}

	sourceString := fmt.Sprintf(npcNickMask, fakeSource, client.nick)

	sendRoleplayMessage(server, client, sourceString, target, false, message)

	return false
}

// NPCA <target> <sourcenick> <text to be sent>
func npcaHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	target := msg.Params[0]
	fakeSource := msg.Params[1]
	message := msg.Params[2]
	sourceString := fmt.Sprintf(npcNickMask, fakeSource, client.nick)

	_, err := CasefoldName(fakeSource)
	if err != nil {
		client.Send(nil, client.server.name, ERR_CANNOTSENDRP, target, client.t("Fake source must be a valid nickname"))
		return false
	}

	sendRoleplayMessage(server, client, sourceString, target, true, message)

	return false
}

// nsHandler handles the /NS and /NICKSERV commands
func nsHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	server.nickservReceivePrivmsg(client, strings.Join(msg.Params, " "))
	return false
}

// OPER <name> <password>
func operHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	name, err := CasefoldName(msg.Params[0])
	if err != nil {
		client.Send(nil, server.name, ERR_PASSWDMISMATCH, client.nick, client.t("Password incorrect"))
		return true
	}
	if client.flags[modes.Operator] == true {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, "OPER", client.t("You're already opered-up!"))
		return false
	}
	server.configurableStateMutex.RLock()
	oper := server.operators[name]
	server.configurableStateMutex.RUnlock()

	password := []byte(msg.Params[1])
	err = passwd.ComparePassword(oper.Pass, password)
	if (oper.Pass == nil) || (err != nil) {
		client.Send(nil, server.name, ERR_PASSWDMISMATCH, client.nick, client.t("Password incorrect"))
		return true
	}

	client.flags[modes.Operator] = true
	client.operName = name
	client.class = oper.Class
	client.whoisLine = oper.WhoisLine

	// push new vhost if one is set
	if len(oper.Vhost) > 0 {
		for fClient := range client.Friends(caps.ChgHost) {
			fClient.SendFromClient("", client, nil, "CHGHOST", client.username, oper.Vhost)
		}
		// CHGHOST requires prefix nickmask to have original hostname, so do that before updating nickmask
		client.vhost = oper.Vhost
		client.updateNickMask("")
	}

	// set new modes
	var applied modes.ModeChanges
	if 0 < len(oper.Modes) {
		modeChanges, unknownChanges := modes.ParseUserModeChanges(strings.Split(oper.Modes, " ")...)
		applied = client.applyUserModeChanges(true, modeChanges)
		if 0 < len(unknownChanges) {
			var runes string
			for r := range unknownChanges {
				runes += string(r)
			}
			client.Notice(fmt.Sprintf(client.t("Could not apply mode changes: +%s"), runes))
		}
	}

	client.Send(nil, server.name, RPL_YOUREOPER, client.nick, client.t("You are now an IRC operator"))

	applied = append(applied, modes.ModeChange{
		Mode: modes.Operator,
		Op:   modes.Add,
	})
	client.Send(nil, server.name, "MODE", client.nick, applied.String())

	server.snomasks.Send(sno.LocalOpers, fmt.Sprintf(ircfmt.Unescape("Client opered up $c[grey][$r%s$c[grey], $r%s$c[grey]]"), client.nickMaskString, client.operName))
	return false
}

// PART <channel>{,<channel>} [<reason>]
func partHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	channels := strings.Split(msg.Params[0], ",")
	var reason string //TODO(dan): if this isn't supplied here, make sure the param doesn't exist in the PART message sent to other users
	if len(msg.Params) > 1 {
		reason = msg.Params[1]
	}

	for _, chname := range channels {
		err := server.channels.Part(client, chname, reason)
		if err == NoSuchChannel {
			client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, chname, client.t("No such channel"))
		}
	}
	return false
}

// PASS <password>
func passHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if client.registered {
		client.Send(nil, server.name, ERR_ALREADYREGISTRED, client.nick, client.t("You may not reregister"))
		return false
	}

	// if no password exists, skip checking
	if len(server.password) == 0 {
		client.authorized = true
		return false
	}

	// check the provided password
	password := []byte(msg.Params[0])
	if passwd.ComparePassword(server.password, password) != nil {
		client.Send(nil, server.name, ERR_PASSWDMISMATCH, client.nick, client.t("Password incorrect"))
		client.Send(nil, server.name, "ERROR", client.t("Password incorrect"))
		return true
	}

	client.authorized = true
	return false
}

// PING <server1> [<server2>]
func pingHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	client.Send(nil, server.name, "PONG", msg.Params...)
	return false
}

// PONG <server> [ <server2> ]
func pongHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// client gets touched when they send this command, so we don't need to do anything
	return false
}

// PRIVMSG <target>{,<target>} <message>
func privmsgHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	clientOnlyTags := GetClientOnlyTags(msg.Tags)
	targets := strings.Split(msg.Params[0], ",")
	message := msg.Params[1]

	// split privmsg
	splitMsg := server.splitMessage(message, !client.capabilities.Has(caps.MaxLine))

	for i, targetString := range targets {
		// max of four targets per privmsg
		if i > maxTargets-1 {
			break
		}
		prefixes, targetString := modes.SplitChannelMembershipPrefixes(targetString)
		lowestPrefix := modes.GetLowestChannelModePrefix(prefixes)

		// eh, no need to notify them
		if len(targetString) < 1 {
			continue
		}

		target, err := CasefoldChannel(targetString)
		if err == nil {
			channel := server.channels.Get(target)
			if channel == nil {
				client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, targetString, client.t("No such channel"))
				continue
			}
			if !channel.CanSpeak(client) {
				client.Send(nil, client.server.name, ERR_CANNOTSENDTOCHAN, channel.name, client.t("Cannot send to channel"))
				continue
			}
			msgid := server.generateMessageID()
			channel.SplitPrivMsg(msgid, lowestPrefix, clientOnlyTags, client, splitMsg)
		} else {
			target, err = CasefoldName(targetString)
			if target == "chanserv" {
				server.chanservReceivePrivmsg(client, message)
				continue
			} else if target == "nickserv" {
				server.nickservReceivePrivmsg(client, message)
				continue
			}
			user := server.clients.Get(target)
			if err != nil || user == nil {
				if len(target) > 0 {
					client.Send(nil, server.name, ERR_NOSUCHNICK, client.nick, target, "No such nick")
				}
				continue
			}
			if !user.capabilities.Has(caps.MessageTags) {
				clientOnlyTags = nil
			}
			msgid := server.generateMessageID()
			// restrict messages appropriately when +R is set
			// intentionally make the sending user think the message went through fine
			if !user.flags[modes.RegisteredOnly] || client.registered {
				user.SendSplitMsgFromClient(msgid, client, clientOnlyTags, "PRIVMSG", user.nick, splitMsg)
			}
			if client.capabilities.Has(caps.EchoMessage) {
				client.SendSplitMsgFromClient(msgid, client, clientOnlyTags, "PRIVMSG", user.nick, splitMsg)
			}
			if user.flags[modes.Away] {
				//TODO(dan): possibly implement cooldown of away notifications to users
				client.Send(nil, server.name, RPL_AWAY, user.nick, user.awayMessage)
			}
		}
	}
	return false
}

// PROXY TCP4/6 SOURCEIP DESTIP SOURCEPORT DESTPORT
// http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
func proxyHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// only allow unregistered clients to use this command
	if client.registered || client.proxiedIP != nil {
		return false
	}

	for _, gateway := range server.ProxyAllowedFrom() {
		if isGatewayAllowed(client.socket.conn.RemoteAddr(), gateway) {
			proxiedIP := msg.Params[1]

			// assume PROXY connections are always secure
			return client.ApplyProxiedIP(proxiedIP, true)
		}
	}
	client.Quit(client.t("PROXY command is not usable from your address"))
	return true
}

// QUIT [<reason>]
func quitHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	reason := "Quit"
	if len(msg.Params) > 0 {
		reason += ": " + msg.Params[0]
	}
	client.Quit(reason)
	return true
}

// REHASH
func rehashHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	server.logger.Info("rehash", fmt.Sprintf("REHASH command used by %s", client.nick))
	err := server.rehash()

	if err == nil {
		client.Send(nil, server.name, RPL_REHASHING, client.nick, "ircd.yaml", client.t("Rehashing"))
	} else {
		server.logger.Error("rehash", fmt.Sprintln("Failed to rehash:", err.Error()))
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, "REHASH", err.Error())
	}
	return false
}

// RENAME <oldchan> <newchan> [<reason>]
func renameHandler(server *Server, client *Client, msg ircmsg.IrcMessage) (result bool) {
	result = false

	errorResponse := func(err error, name string) {
		// TODO: send correct error codes, e.g., ERR_CANNOTRENAME, ERR_CHANNAMEINUSE
		var code string
		switch err {
		case NoSuchChannel:
			code = ERR_NOSUCHCHANNEL
		case RenamePrivsNeeded:
			code = ERR_CHANOPRIVSNEEDED
		case InvalidChannelName:
			code = ERR_UNKNOWNERROR
		case ChannelNameInUse:
			code = ERR_UNKNOWNERROR
		default:
			code = ERR_UNKNOWNERROR
		}
		client.Send(nil, server.name, code, client.Nick(), "RENAME", name, err.Error())
	}

	oldName := strings.TrimSpace(msg.Params[0])
	newName := strings.TrimSpace(msg.Params[1])
	if oldName == "" || newName == "" {
		errorResponse(InvalidChannelName, "<empty>")
		return
	}
	casefoldedOldName, err := CasefoldChannel(oldName)
	if err != nil {
		errorResponse(InvalidChannelName, oldName)
		return
	}

	reason := "No reason"
	if 2 < len(msg.Params) {
		reason = msg.Params[2]
	}

	channel := server.channels.Get(oldName)
	if channel == nil {
		errorResponse(NoSuchChannel, oldName)
		return
	}
	//TODO(dan): allow IRCops to do this?
	if !channel.ClientIsAtLeast(client, modes.Operator) {
		errorResponse(RenamePrivsNeeded, oldName)
		return
	}

	founder := channel.Founder()
	if founder != "" && founder != client.AccountName() {
		//TODO(dan): Change this to ERR_CANNOTRENAME
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, "RENAME", oldName, client.t("Only channel founders can change registered channels"))
		return false
	}

	// perform the channel rename
	err = server.channels.Rename(oldName, newName)
	if err != nil {
		errorResponse(err, newName)
		return
	}

	// rename succeeded, persist it
	go server.channelRegistry.Rename(channel, casefoldedOldName)

	// send RENAME messages
	for _, mcl := range channel.Members() {
		if mcl.capabilities.Has(caps.Rename) {
			mcl.Send(nil, client.nickMaskString, "RENAME", oldName, newName, reason)
		} else {
			mcl.Send(nil, mcl.nickMaskString, "PART", oldName, fmt.Sprintf(mcl.t("Channel renamed: %s"), reason))
			if mcl.capabilities.Has(caps.ExtendedJoin) {
				accountName := "*"
				if mcl.account != nil {
					accountName = mcl.account.Name
				}
				mcl.Send(nil, mcl.nickMaskString, "JOIN", newName, accountName, mcl.realname)
			} else {
				mcl.Send(nil, mcl.nickMaskString, "JOIN", newName)
			}
		}
	}

	return false
}

// RESUME <oldnick> [timestamp]
func resumeHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	oldnick := msg.Params[0]

	if strings.Contains(oldnick, " ") {
		client.Send(nil, server.name, ERR_CANNOT_RESUME, "*", client.t("Cannot resume connection, old nickname contains spaces"))
		return false
	}

	if client.Registered() {
		client.Send(nil, server.name, ERR_CANNOT_RESUME, oldnick, client.t("Cannot resume connection, connection registration has already been completed"))
		return false
	}

	var timestamp *time.Time
	if 1 < len(msg.Params) {
		ts, err := time.Parse("2006-01-02T15:04:05.999Z", msg.Params[1])
		if err == nil {
			timestamp = &ts
		} else {
			client.Send(nil, server.name, ERR_CANNOT_RESUME, oldnick, client.t("Timestamp is not in 2006-01-02T15:04:05.999Z format, ignoring it"))
		}
	}

	client.resumeDetails = &ResumeDetails{
		OldNick:   oldnick,
		Timestamp: timestamp,
	}

	return false
}

// SANICK <oldnick> <nickname>
func sanickHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	targetNick := strings.TrimSpace(msg.Params[0])
	target := server.clients.Get(targetNick)
	if target == nil {
		client.Send(nil, server.name, ERR_NOSUCHNICK, client.nick, msg.Params[0], client.t("No such nick"))
		return false
	}
	return performNickChange(server, client, target, msg.Params[1])
}

// SCENE <target> <text to be sent>
func sceneHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	target := msg.Params[0]
	message := msg.Params[1]
	sourceString := fmt.Sprintf(sceneNickMask, client.nick)

	sendRoleplayMessage(server, client, sourceString, target, false, message)

	return false
}

// TAGMSG <target>{,<target>}
func tagmsgHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	clientOnlyTags := GetClientOnlyTags(msg.Tags)
	// no client-only tags, so we can drop it
	if clientOnlyTags == nil {
		return false
	}

	targets := strings.Split(msg.Params[0], ",")

	for i, targetString := range targets {
		// max of four targets per privmsg
		if i > maxTargets-1 {
			break
		}
		prefixes, targetString := modes.SplitChannelMembershipPrefixes(targetString)
		lowestPrefix := modes.GetLowestChannelModePrefix(prefixes)

		// eh, no need to notify them
		if len(targetString) < 1 {
			continue
		}

		target, err := CasefoldChannel(targetString)
		if err == nil {
			channel := server.channels.Get(target)
			if channel == nil {
				client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, targetString, client.t("No such channel"))
				continue
			}
			if !channel.CanSpeak(client) {
				client.Send(nil, client.server.name, ERR_CANNOTSENDTOCHAN, channel.name, client.t("Cannot send to channel"))
				continue
			}
			msgid := server.generateMessageID()

			channel.TagMsg(msgid, lowestPrefix, clientOnlyTags, client)
		} else {
			target, err = CasefoldName(targetString)
			user := server.clients.Get(target)
			if err != nil || user == nil {
				if len(target) > 0 {
					client.Send(nil, server.name, ERR_NOSUCHNICK, client.nick, target, client.t("No such nick"))
				}
				continue
			}
			msgid := server.generateMessageID()

			// end user can't receive tagmsgs
			if !user.capabilities.Has(caps.MessageTags) {
				continue
			}
			user.SendFromClient(msgid, client, clientOnlyTags, "TAGMSG", user.nick)
			if client.capabilities.Has(caps.EchoMessage) {
				client.SendFromClient(msgid, client, clientOnlyTags, "TAGMSG", user.nick)
			}
			if user.flags[modes.Away] {
				//TODO(dan): possibly implement cooldown of away notifications to users
				client.Send(nil, server.name, RPL_AWAY, user.nick, user.awayMessage)
			}
		}
	}
	return false
}

// TIME [<server>]
func timeHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var target string
	if len(msg.Params) > 0 {
		target = msg.Params[0]
	}
	casefoldedTarget, err := Casefold(target)
	if (target != "") && err != nil || (casefoldedTarget != server.nameCasefolded) {
		client.Send(nil, server.name, ERR_NOSUCHSERVER, client.nick, target, client.t("No such server"))
		return false
	}
	client.Send(nil, server.name, RPL_TIME, client.nick, server.name, time.Now().Format(time.RFC1123))
	return false
}

// TOPIC <channel> [<topic>]
func topicHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	name, err := CasefoldChannel(msg.Params[0])
	channel := server.channels.Get(name)
	if err != nil || channel == nil {
		if len(msg.Params[0]) > 0 {
			client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, msg.Params[0], client.t("No such channel"))
		}
		return false
	}

	if len(msg.Params) > 1 {
		channel.SetTopic(client, msg.Params[1])
	} else {
		channel.SendTopic(client)
	}
	return false
}

// UNDLINE
func unDLineHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// check oper permissions
	if !client.class.Capabilities["oper:local_unban"] {
		client.Send(nil, server.name, ERR_NOPRIVS, client.nick, msg.Command, client.t("Insufficient oper privs"))
		return false
	}

	// get host
	hostString := msg.Params[0]

	// check host
	var hostAddr net.IP
	var hostNet *net.IPNet

	_, hostNet, err := net.ParseCIDR(hostString)
	if err != nil {
		hostAddr = net.ParseIP(hostString)
	}

	if hostAddr == nil && hostNet == nil {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("Could not parse IP address or CIDR network"))
		return false
	}

	if hostNet == nil {
		hostString = hostAddr.String()
	} else {
		hostString = hostNet.String()
	}

	// save in datastore
	err = server.store.Update(func(tx *buntdb.Tx) error {
		dlineKey := fmt.Sprintf(keyDlineEntry, hostString)

		// check if it exists or not
		val, err := tx.Get(dlineKey)
		if val == "" {
			return errNoExistingBan
		} else if err != nil {
			return err
		}

		tx.Delete(dlineKey)
		return nil
	})

	if err != nil {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, fmt.Sprintf(client.t("Could not remove ban [%s]"), err.Error()))
		return false
	}

	if hostNet == nil {
		server.dlines.RemoveIP(hostAddr)
	} else {
		server.dlines.RemoveNetwork(*hostNet)
	}

	client.Notice(fmt.Sprintf(client.t("Removed D-Line for %s"), hostString))
	server.snomasks.Send(sno.LocalXline, fmt.Sprintf(ircfmt.Unescape("%s$r removed D-Line for %s"), client.nick, hostString))
	return false
}

// UNKLINE
func unKLineHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// check oper permissions
	if !client.class.Capabilities["oper:local_unban"] {
		client.Send(nil, server.name, ERR_NOPRIVS, client.nick, msg.Command, client.t("Insufficient oper privs"))
		return false
	}

	// get host
	mask := msg.Params[0]

	if !strings.Contains(mask, "!") && !strings.Contains(mask, "@") {
		mask = mask + "!*@*"
	} else if !strings.Contains(mask, "@") {
		mask = mask + "@*"
	}

	// save in datastore
	err := server.store.Update(func(tx *buntdb.Tx) error {
		klineKey := fmt.Sprintf(keyKlineEntry, mask)

		// check if it exists or not
		val, err := tx.Get(klineKey)
		if val == "" {
			return errNoExistingBan
		} else if err != nil {
			return err
		}

		tx.Delete(klineKey)
		return nil
	})

	if err != nil {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, fmt.Sprintf(client.t("Could not remove ban [%s]"), err.Error()))
		return false
	}

	server.klines.RemoveMask(mask)

	client.Notice(fmt.Sprintf(client.t("Removed K-Line for %s"), mask))
	server.snomasks.Send(sno.LocalXline, fmt.Sprintf(ircfmt.Unescape("%s$r removed K-Line for %s"), client.nick, mask))
	return false
}

// USER <username> * 0 <realname>
func userHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if client.registered {
		client.Send(nil, server.name, ERR_ALREADYREGISTRED, client.nick, client.t("You may not reregister"))
		return false
	}

	if !client.authorized {
		client.Quit("Bad password")
		return true
	}

	if client.username != "" && client.realname != "" {
		return false
	}

	// confirm that username is valid
	//
	_, err := CasefoldName(msg.Params[0])
	if err != nil {
		client.Send(nil, "", "ERROR", client.t("Malformed username"))
		return true
	}

	if !client.HasUsername() {
		client.username = "~" + msg.Params[0]
		// don't bother updating nickmask here, it's not valid anyway
	}
	if client.realname == "" {
		client.realname = msg.Params[3]
	}

	server.tryRegister(client)

	return false
}

// USERHOST <nickname> [<nickname> <nickname> ...]
func userhostHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	returnedNicks := make(map[string]bool)

	for i, nickname := range msg.Params {
		if i >= 10 {
			break
		}

		casefoldedNickname, err := CasefoldName(nickname)
		target := server.clients.Get(casefoldedNickname)
		if err != nil || target == nil {
			client.Send(nil, client.server.name, ERR_NOSUCHNICK, client.nick, nickname, client.t("No such nick"))
			return false
		}
		if returnedNicks[casefoldedNickname] {
			continue
		}

		// to prevent returning multiple results for a single nick
		returnedNicks[casefoldedNickname] = true

		var isOper, isAway string

		if target.flags[modes.Operator] {
			isOper = "*"
		}
		if target.flags[modes.Away] {
			isAway = "-"
		} else {
			isAway = "+"
		}
		client.Send(nil, client.server.name, RPL_USERHOST, client.nick, fmt.Sprintf("%s%s=%s%s@%s", target.nick, isOper, isAway, target.username, target.hostname))
	}

	return false
}

// VERSION [<server>]
func versionHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var target string
	if len(msg.Params) > 0 {
		target = msg.Params[0]
	}
	casefoldedTarget, err := Casefold(target)
	if target != "" && (err != nil || casefoldedTarget != server.nameCasefolded) {
		client.Send(nil, server.name, ERR_NOSUCHSERVER, client.nick, target, client.t("No such server"))
		return false
	}

	client.Send(nil, server.name, RPL_VERSION, client.nick, Ver, server.name)
	client.RplISupport()
	return false
}

// WEBIRC <password> <gateway> <hostname> <ip> [:flag1 flag2=x flag3]
func webircHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
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
				if client.flags[modes.TLS] || utils.AddrIsLocal(client.socket.conn.RemoteAddr()) {
					secure = true
				}
			}
		}
	}

	for _, info := range server.WebIRCConfig() {
		for _, gateway := range info.Hosts {
			if isGatewayAllowed(client.socket.conn.RemoteAddr(), gateway) {
				// confirm password and/or fingerprint
				givenPassword := msg.Params[0]
				if 0 < len(info.Password) && passwd.ComparePasswordString(info.Password, givenPassword) != nil {
					continue
				}
				if 0 < len(info.Fingerprint) && client.certfp != info.Fingerprint {
					continue
				}

				proxiedIP := msg.Params[3]
				return client.ApplyProxiedIP(proxiedIP, secure)
			}
		}
	}

	client.Quit(client.t("WEBIRC command is not usable from your address or incorrect password given"))
	return true
}

// WHO [ <mask> [ "o" ] ]
func whoHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if msg.Params[0] == "" {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, "WHO", client.t("First param must be a mask or channel"))
		return false
	}

	var mask string
	if len(msg.Params) > 0 {
		casefoldedMask, err := Casefold(msg.Params[0])
		if err != nil {
			client.Send(nil, server.name, ERR_UNKNOWNERROR, "WHO", client.t("Mask isn't valid"))
			return false
		}
		mask = casefoldedMask
	}

	friends := client.Friends()

	//TODO(dan): is this used and would I put this param in the Modern doc?
	// if not, can we remove it?
	//var operatorOnly bool
	//if len(msg.Params) > 1 && msg.Params[1] == "o" {
	//	operatorOnly = true
	//}

	if mask[0] == '#' {
		// TODO implement wildcard matching
		//TODO(dan): ^ only for opers
		channel := server.channels.Get(mask)
		if channel != nil {
			whoChannel(client, channel, friends)
		}
	} else {
		for mclient := range server.clients.FindAll(mask) {
			client.rplWhoReply(nil, mclient)
		}
	}

	client.Send(nil, server.name, RPL_ENDOFWHO, client.nick, mask, client.t("End of WHO list"))
	return false
}

// WHOIS [ <target> ] <mask> *( "," <mask> )
func whoisHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var masksString string
	//var target string

	if len(msg.Params) > 1 {
		//target = msg.Params[0]
		masksString = msg.Params[1]
	} else {
		masksString = msg.Params[0]
	}

	if len(strings.TrimSpace(masksString)) < 1 {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("No masks given"))
		return false
	}

	if client.flags[modes.Operator] {
		masks := strings.Split(masksString, ",")
		for _, mask := range masks {
			casefoldedMask, err := Casefold(mask)
			if err != nil {
				client.Send(nil, client.server.name, ERR_NOSUCHNICK, client.nick, mask, client.t("No such nick"))
				continue
			}
			matches := server.clients.FindAll(casefoldedMask)
			if len(matches) == 0 {
				client.Send(nil, client.server.name, ERR_NOSUCHNICK, client.nick, mask, client.t("No such nick"))
				continue
			}
			for mclient := range matches {
				client.getWhoisOf(mclient)
			}
		}
	} else {
		// only get the first request
		casefoldedMask, err := Casefold(strings.Split(masksString, ",")[0])
		mclient := server.clients.Get(casefoldedMask)
		if err != nil || mclient == nil {
			client.Send(nil, client.server.name, ERR_NOSUCHNICK, client.nick, masksString, client.t("No such nick"))
			// fall through, ENDOFWHOIS is always sent
		} else {
			client.getWhoisOf(mclient)
		}
	}
	client.Send(nil, server.name, RPL_ENDOFWHOIS, client.nick, masksString, client.t("End of /WHOIS list"))
	return false
}

// WHOWAS <nickname> [<count> [<server>]]
func whowasHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	nicknames := strings.Split(msg.Params[0], ",")

	var count int64
	if len(msg.Params) > 1 {
		count, _ = strconv.ParseInt(msg.Params[1], 10, 64)
	}
	//var target string
	//if len(msg.Params) > 2 {
	//	target = msg.Params[2]
	//}
	for _, nickname := range nicknames {
		results := server.whoWas.Find(nickname, count)
		if len(results) == 0 {
			if len(nickname) > 0 {
				client.Send(nil, server.name, ERR_WASNOSUCHNICK, client.nick, nickname, client.t("There was no such nickname"))
			}
		} else {
			for _, whoWas := range results {
				client.Send(nil, server.name, RPL_WHOWASUSER, client.nick, whoWas.nickname, whoWas.username, whoWas.hostname, "*", whoWas.realname)
			}
		}
		if len(nickname) > 0 {
			client.Send(nil, server.name, RPL_ENDOFWHOWAS, client.nick, nickname, client.t("End of WHOWAS"))
		}
	}
	return false
}
