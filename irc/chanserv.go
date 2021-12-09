// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/sno"
	"github.com/ergochat/ergo/irc/utils"
	"github.com/ergochat/irc-go/ircfmt"
)

const chanservHelp = `ChanServ lets you register and manage channels.`

func chanregEnabled(config *Config) bool {
	return config.Channels.Registration.Enabled
}

var (
	chanservCommands = map[string]*serviceCommand{
		"op": {
			handler: csOpHandler,
			help: `Syntax: $bOP #channel [nickname]$b

OP makes the given nickname, or yourself, a channel admin. You can only use
this command if you're a founder or in the AMODEs of the channel.`,
			helpShort:    `$bOP$b makes the given user (or yourself) a channel admin.`,
			authRequired: true,
			enabled:      chanregEnabled,
			minParams:    1,
		},
		"deop": {
			handler: csDeopHandler,
			help: `Syntax: $bDEOP #channel [nickname]$b

DEOP removes the given nickname, or yourself, the channel admin. You can only use
this command if you're the founder of the channel.`,
			helpShort: `$bDEOP$b removes the given user (or yourself) from a channel admin.`,
			enabled:   chanregEnabled,
			minParams: 1,
		},
		"register": {
			handler: csRegisterHandler,
			help: `Syntax: $bREGISTER #channel$b

REGISTER lets you own the given channel. If you rejoin this channel, you'll be
given admin privs on it. Modes set on the channel and the topic will also be
remembered.`,
			helpShort:    `$bREGISTER$b lets you own a given channel.`,
			authRequired: true,
			enabled:      chanregEnabled,
			minParams:    1,
		},
		"unregister": {
			handler: csUnregisterHandler,
			help: `Syntax: $bUNREGISTER #channel [code]$b

UNREGISTER deletes a channel registration, allowing someone else to claim it.
To prevent accidental unregistrations, a verification code is required;
invoking the command without a code will display the necessary code.`,
			helpShort: `$bUNREGISTER$b deletes a channel registration.`,
			enabled:   chanregEnabled,
			minParams: 1,
		},
		"drop": {
			aliasOf: "unregister",
		},
		"amode": {
			handler: csAmodeHandler,
			help: `Syntax: $bAMODE #channel [mode change] [account]$b

AMODE lists or modifies persistent mode settings that affect channel members.
For example, $bAMODE #channel +o dan$b grants the holder of the "dan"
account the +o operator mode every time they join #channel. To list current
accounts and modes, use $bAMODE #channel$b. Note that users are always
referenced by their registered account names, not their nicknames.
The permissions hierarchy for adding and removing modes is the same as in
the ordinary /MODE command.`,
			helpShort: `$bAMODE$b modifies persistent mode settings for channel members.`,
			enabled:   chanregEnabled,
			minParams: 1,
		},
		"clear": {
			handler: csClearHandler,
			help: `Syntax: $bCLEAR #channel target$b

CLEAR removes users or settings from a channel. Specifically:

$bCLEAR #channel users$b kicks all users except for you.
$bCLEAR #channel access$b resets all stored bans, invites, ban exceptions,
and persistent user-mode grants made with CS AMODE.`,
			helpShort: `$bCLEAR$b removes users or settings from a channel.`,
			enabled:   chanregEnabled,
			minParams: 2,
		},
		"transfer": {
			handler: csTransferHandler,
			help: `Syntax: $bTRANSFER [accept] #channel user [code]$b

TRANSFER transfers ownership of a channel from one user to another.
To prevent accidental transfers, a verification code is required. For
example, $bTRANSFER #channel alice$b displays the required confirmation
code, then $bTRANSFER #channel alice 2930242125$b initiates the transfer.
Unless you are an IRC operator with the correct permissions, alice must
then accept the transfer, which she can do with $bTRANSFER accept #channel$b.
To cancel a pending transfer, transfer the channel to yourself.`,
			helpShort: `$bTRANSFER$b transfers ownership of a channel to another user.`,
			enabled:   chanregEnabled,
			minParams: 2,
		},
		"purge": {
			handler: csPurgeHandler,
			help: `Syntax: $bPURGE <ADD | DEL | LIST> #channel [code] [reason]$b

PURGE ADD blacklists a channel from the server, making it impossible to join
or otherwise interact with the channel. If the channel currently has members,
they will be kicked from it. PURGE may also be applied preemptively to
channels that do not currently have members. A purge can be undone with
PURGE DEL. To list purged channels, use PURGE LIST.`,
			helpShort:         `$bPURGE$b blacklists a channel from the server.`,
			capabs:            []string{"chanreg"},
			minParams:         1,
			maxParams:         3,
			unsplitFinalParam: true,
		},
		"list": {
			handler: csListHandler,
			help: `Syntax: $bLIST [regex]$b

LIST returns the list of registered channels, which match the given regex.
If no regex is provided, all registered channels are returned.`,
			helpShort: `$bLIST$b searches the list of registered channels.`,
			capabs:    []string{"chanreg"},
			minParams: 0,
		},
		"info": {
			handler: csInfoHandler,
			help: `Syntax: $INFO #channel$b

INFO displays info about a registered channel.`,
			helpShort: `$bINFO$b displays info about a registered channel.`,
			enabled:   chanregEnabled,
		},
		"get": {
			handler: csGetHandler,
			help: `Syntax: $bGET #channel <setting>$b

GET queries the current values of the channel settings. For more information
on the settings and their possible values, see HELP SET.`,
			helpShort: `$bGET$b queries the current values of a channel's settings`,
			enabled:   chanregEnabled,
			minParams: 2,
		},
		"set": {
			handler:   csSetHandler,
			helpShort: `$bSET$b modifies a channel's settings`,
			// these are broken out as separate strings so they can be translated separately
			helpStrings: []string{
				`Syntax $bSET #channel <setting> <value>$b

SET modifies a channel's settings. The following settings are available:`,

				`$bHISTORY$b
'history' lets you control how channel history is stored. Your options are:
1. 'off'        [no history]
2. 'ephemeral'  [a limited amount of temporary history, not stored on disk]
3. 'on'         [history stored in a permanent database, if available]
4. 'default'    [use the server default]`,
				`$bQUERY-CUTOFF$b
'query-cutoff' lets you restrict how much channel history can be retrieved
by unprivileged users. Your options are:
1. 'none'               [no restrictions]
2. 'registration-time'  [users can view history from after their account was
                         registered, plus a grace period]
3. 'join-time'          [users can view history from after they joined the
                         channel; note that history will be effectively
                         unavailable to clients that are not always-on]
4. 'default'            [use the server default]`,
			},
			enabled:   chanregEnabled,
			minParams: 3,
		},
		"howtoban": {
			handler:   csHowToBanHandler,
			helpShort: `$bHOWTOBAN$b suggests the best available way of banning a user`,
			help: `Syntax: $bHOWTOBAN #channel <nick>

The best way to ban a user from a channel will depend on how they are
connected to the server. $bHOWTOBAN$b suggests a ban command that will
(ideally) prevent the user from returning to the channel.`,
			enabled:   chanregEnabled,
			minParams: 2,
		},
	}
)

func csAmodeHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	channelName := params[0]

	channel := server.channels.Get(channelName)
	if channel == nil {
		service.Notice(rb, client.t("Channel does not exist"))
		return
	} else if channel.Founder() == "" {
		service.Notice(rb, client.t("Channel is not registered"))
		return
	}

	modeChanges, unknown := modes.ParseChannelModeChanges(params[1:]...)
	var change modes.ModeChange
	if len(modeChanges) > 1 || len(unknown) > 0 {
		service.Notice(rb, client.t("Invalid mode change"))
		return
	} else if len(modeChanges) == 1 {
		change = modeChanges[0]
	} else {
		change = modes.ModeChange{Op: modes.List}
	}

	// normalize and validate the account argument
	accountIsValid := false
	change.Arg, _ = CasefoldName(change.Arg)
	switch change.Op {
	case modes.List:
		accountIsValid = true
	case modes.Add:
		// if we're adding a mode, the account must exist
		if change.Arg != "" {
			_, err := server.accounts.LoadAccount(change.Arg)
			accountIsValid = (err == nil)
		}
	case modes.Remove:
		// allow removal of accounts that may have been deleted
		accountIsValid = (change.Arg != "")
	}
	if !accountIsValid {
		service.Notice(rb, client.t("Account does not exist"))
		return
	}

	affectedModes, err := channel.ProcessAccountToUmodeChange(client, change)

	if err == errInsufficientPrivs {
		service.Notice(rb, client.t("Insufficient privileges"))
		return
	} else if err != nil {
		service.Notice(rb, client.t("Internal error"))
		return
	}

	switch change.Op {
	case modes.List:
		// sort the persistent modes in descending order of priority
		sort.Slice(affectedModes, func(i, j int) bool {
			return umodeGreaterThan(affectedModes[i].Mode, affectedModes[j].Mode)
		})
		service.Notice(rb, fmt.Sprintf(client.t("Channel %[1]s has %[2]d persistent modes set"), channelName, len(affectedModes)))
		for _, modeChange := range affectedModes {
			service.Notice(rb, fmt.Sprintf(client.t("Account %[1]s receives mode +%[2]s"), modeChange.Arg, string(modeChange.Mode)))
		}
	case modes.Add, modes.Remove:
		if len(affectedModes) > 0 {
			service.Notice(rb, fmt.Sprintf(client.t("Successfully set persistent mode %[1]s on %[2]s"), strings.Join([]string{string(change.Op), string(change.Mode)}, ""), change.Arg))
			// #729: apply change to current membership
			for _, member := range channel.Members() {
				if member.Account() == change.Arg {
					// applyModeToMember takes the nickname, not the account name,
					// so translate:
					modeChange := change
					modeChange.Arg = member.Nick()
					applied, modeChange := channel.applyModeToMember(client, modeChange, rb)
					if applied {
						announceCmodeChanges(channel, modes.ModeChanges{modeChange}, server.name, "*", "", false, rb)
					}
				}
			}
		} else {
			service.Notice(rb, client.t("No changes were made"))
		}
	}
}

func csOpHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	channelInfo := server.channels.Get(params[0])
	if channelInfo == nil {
		service.Notice(rb, client.t("Channel does not exist"))
		return
	}
	channelName := channelInfo.Name()
	founder := channelInfo.Founder()

	clientAccount := client.Account()
	if clientAccount == "" {
		service.Notice(rb, client.t("You're not logged into an account"))
		return
	}

	var target *Client
	if len(params) > 1 {
		target = server.clients.Get(params[1])
		if target == nil {
			service.Notice(rb, client.t("Could not find given client"))
			return
		}
	} else {
		target = client
	}

	var givenMode modes.Mode
	if target == client {
		if clientAccount == founder {
			givenMode = modes.ChannelFounder
		} else {
			givenMode = channelInfo.getAmode(clientAccount)
			if givenMode == modes.Mode(0) {
				service.Notice(rb, client.t("You don't have any stored privileges on that channel"))
				return
			}
		}
	} else {
		if clientAccount == founder {
			givenMode = modes.ChannelOperator
		} else {
			service.Notice(rb, client.t("Only the channel founder can do this"))
			return
		}
	}

	applied, change := channelInfo.applyModeToMember(client,
		modes.ModeChange{Mode: givenMode,
			Op:  modes.Add,
			Arg: target.NickCasefolded(),
		},
		rb)
	if applied {
		announceCmodeChanges(channelInfo, modes.ModeChanges{change}, server.name, "*", "", false, rb)
	}

	service.Notice(rb, client.t("Successfully granted operator privileges"))

	tnick := target.Nick()
	server.logger.Info("services", fmt.Sprintf("Client %s op'd [%s] in channel %s", client.Nick(), tnick, channelName))
	server.snomasks.Send(sno.LocalChannels, fmt.Sprintf(ircfmt.Unescape("Client $c[grey][$r%s$c[grey]] CS OP'd $c[grey][$r%s$c[grey]] in channel $c[grey][$r%s$c[grey]]"), client.NickMaskString(), tnick, channelName))
}

func csDeopHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	channel := server.channels.Get(params[0])
	if channel == nil {
		service.Notice(rb, client.t("Channel does not exist"))
		return
	}
	if !channel.hasClient(client) {
		service.Notice(rb, client.t("You're not on that channel"))
		return
	}

	var target *Client
	if len(params) > 1 {
		target = server.clients.Get(params[1])
		if target == nil {
			service.Notice(rb, client.t("Could not find given client"))
			return
		}
	} else {
		target = client
	}

	present, _, cumodes := channel.ClientStatus(target)
	if !present || len(cumodes) == 0 {
		service.Notice(rb, client.t("Target has no privileges to remove"))
		return
	}

	tnick := target.Nick()
	modeChanges := make(modes.ModeChanges, len(cumodes))
	for i, mode := range cumodes {
		modeChanges[i] = modes.ModeChange{
			Mode: mode,
			Op:   modes.Remove,
			Arg:  tnick,
		}
	}

	// use the user's own permissions for the check, then announce
	// the changes as coming from chanserv
	applied := channel.ApplyChannelModeChanges(client, false, modeChanges, rb)
	details := client.Details()
	isBot := client.HasMode(modes.Bot)
	announceCmodeChanges(channel, applied, details.nickMask, details.accountName, details.account, isBot, rb)

	if len(applied) == 0 {
		return
	}

	service.Notice(rb, client.t("Successfully removed operator privileges"))
}

func csRegisterHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	if server.Config().Channels.Registration.OperatorOnly && !client.HasRoleCapabs("chanreg") {
		service.Notice(rb, client.t("Channel registration is restricted to server operators"))
		return
	}
	channelName := params[0]
	channelInfo := server.channels.Get(channelName)
	if channelInfo == nil {
		service.Notice(rb, client.t("No such channel"))
		return
	}
	if !channelInfo.ClientIsAtLeast(client, modes.ChannelOperator) {
		service.Notice(rb, client.t("You must be an oper on the channel to register it"))
		return
	}

	account := client.Account()
	if !checkChanLimit(service, client, rb) {
		return
	}

	// this provides the synchronization that allows exactly one registration of the channel:
	err := server.channels.SetRegistered(channelName, account)
	if err != nil {
		service.Notice(rb, err.Error())
		return
	}

	service.Notice(rb, fmt.Sprintf(client.t("Channel %s successfully registered"), channelName))

	server.logger.Info("services", fmt.Sprintf("Client %s registered channel %s", client.Nick(), channelName))
	server.snomasks.Send(sno.LocalChannels, fmt.Sprintf(ircfmt.Unescape("Channel registered $c[grey][$r%s$c[grey]] by $c[grey][$r%s$c[grey]]"), channelName, client.nickMaskString))

	// give them founder privs
	applied, change := channelInfo.applyModeToMember(client,
		modes.ModeChange{
			Mode: modes.ChannelFounder,
			Op:   modes.Add,
			Arg:  client.NickCasefolded(),
		},
		rb)
	if applied {
		announceCmodeChanges(channelInfo, modes.ModeChanges{change}, service.prefix, "*", "", false, rb)
	}
}

// check whether a client has already registered too many channels
func checkChanLimit(service *ircService, client *Client, rb *ResponseBuffer) (ok bool) {
	account := client.Account()
	channelsAlreadyRegistered := client.server.accounts.ChannelsForAccount(account)
	ok = len(channelsAlreadyRegistered) < client.server.Config().Channels.Registration.MaxChannelsPerAccount || client.HasRoleCapabs("chanreg")
	if !ok {
		service.Notice(rb, client.t("You have already registered the maximum number of channels; try dropping some with /CS UNREGISTER"))
	}
	return
}

func csPrivsCheck(service *ircService, channel RegisteredChannel, client *Client, rb *ResponseBuffer) (success bool) {
	founder := channel.Founder
	if founder == "" {
		service.Notice(rb, client.t("That channel is not registered"))
		return false
	}
	if client.HasRoleCapabs("chanreg") {
		return true
	}
	if founder != client.Account() {
		service.Notice(rb, client.t("Insufficient privileges"))
		return false
	}
	return true
}

func csUnregisterHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	channelName := params[0]
	var verificationCode string
	if len(params) > 1 {
		verificationCode = params[1]
	}

	channel := server.channels.Get(channelName)
	if channel == nil {
		service.Notice(rb, client.t("No such channel"))
		return
	}

	info := channel.ExportRegistration(0)
	channelKey := info.NameCasefolded
	if !csPrivsCheck(service, info, client, rb) {
		return
	}

	expectedCode := utils.ConfirmationCode(info.Name, info.RegisteredAt)
	if expectedCode != verificationCode {
		service.Notice(rb, ircfmt.Unescape(client.t("$bWarning: unregistering this channel will remove all stored channel attributes.$b")))
		service.Notice(rb, fmt.Sprintf(client.t("To confirm, run this command: %s"), fmt.Sprintf("/CS UNREGISTER %s %s", channelKey, expectedCode)))
		return
	}

	server.channels.SetUnregistered(channelKey, info.Founder)
	service.Notice(rb, fmt.Sprintf(client.t("Channel %s is now unregistered"), channelKey))
}

func csClearHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	channel := server.channels.Get(params[0])
	if channel == nil {
		service.Notice(rb, client.t("Channel does not exist"))
		return
	}
	if !csPrivsCheck(service, channel.ExportRegistration(0), client, rb) {
		return
	}

	switch strings.ToLower(params[1]) {
	case "access":
		channel.resetAccess()
		service.Notice(rb, client.t("Successfully reset channel access"))
	case "users":
		for _, target := range channel.Members() {
			if target != client {
				channel.Kick(client, target, "Cleared by ChanServ", rb, true)
			}
		}
	default:
		service.Notice(rb, client.t("Invalid parameters"))
	}

}

func csTransferHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	if strings.ToLower(params[0]) == "accept" {
		processTransferAccept(service, client, params[1], rb)
		return
	}
	chname := params[0]
	channel := server.channels.Get(chname)
	if channel == nil {
		service.Notice(rb, client.t("Channel does not exist"))
		return
	}
	regInfo := channel.ExportRegistration(0)
	chname = regInfo.Name
	account := client.Account()
	isFounder := account != "" && account == regInfo.Founder
	oper := client.Oper()
	hasPrivs := oper.HasRoleCapab("chanreg")
	if !isFounder && !hasPrivs {
		service.Notice(rb, client.t("Insufficient privileges"))
		return
	}
	target := params[1]
	targetAccount, err := server.accounts.LoadAccount(params[1])
	if err != nil {
		service.Notice(rb, client.t("Account does not exist"))
		return
	}
	if targetAccount.NameCasefolded != account {
		expectedCode := utils.ConfirmationCode(regInfo.Name, regInfo.RegisteredAt)
		codeValidated := 2 < len(params) && params[2] == expectedCode
		if !codeValidated {
			service.Notice(rb, ircfmt.Unescape(client.t("$bWarning: you are about to transfer control of your channel to another user.$b")))
			service.Notice(rb, fmt.Sprintf(client.t("To confirm your channel transfer, type: /CS TRANSFER %[1]s %[2]s %[3]s"), chname, target, expectedCode))
			return
		}
	}
	if !isFounder {
		message := fmt.Sprintf("Operator %s ran CS TRANSFER on %s to account %s", oper.Name, chname, target)
		server.snomasks.Send(sno.LocalOpers, message)
		server.logger.Info("opers", message)
	}
	status, err := channel.Transfer(client, target, hasPrivs)
	if err == nil {
		switch status {
		case channelTransferComplete:
			service.Notice(rb, fmt.Sprintf(client.t("Successfully transferred channel %[1]s to account %[2]s"), chname, target))
		case channelTransferPending:
			sendTransferPendingNotice(service, server, target, chname)
			service.Notice(rb, fmt.Sprintf(client.t("Transfer of channel %[1]s to account %[2]s succeeded, pending acceptance"), chname, target))
		case channelTransferCancelled:
			service.Notice(rb, fmt.Sprintf(client.t("Cancelled pending transfer of channel %s"), chname))
		}
	} else {
		switch err {
		case errChannelNotOwnedByAccount:
			service.Notice(rb, client.t("You don't own that channel"))
		default:
			service.Notice(rb, client.t("Could not transfer channel"))
		}
	}
}

func sendTransferPendingNotice(service *ircService, server *Server, account, chname string) {
	clients := server.accounts.AccountToClients(account)
	if len(clients) == 0 {
		return
	}
	var client *Client
	for _, candidate := range clients {
		client = candidate
		if candidate.NickCasefolded() == candidate.Account() {
			break // prefer the login where the nick is the account
		}
	}
	client.Send(nil, service.prefix, "NOTICE", client.Nick(), fmt.Sprintf(client.t("You have been offered ownership of channel %[1]s. To accept, /CS TRANSFER ACCEPT %[1]s"), chname))
}

func processTransferAccept(service *ircService, client *Client, chname string, rb *ResponseBuffer) {
	channel := client.server.channels.Get(chname)
	if channel == nil {
		service.Notice(rb, client.t("Channel does not exist"))
		return
	}
	if !checkChanLimit(service, client, rb) {
		return
	}
	switch channel.AcceptTransfer(client) {
	case nil:
		service.Notice(rb, fmt.Sprintf(client.t("Successfully accepted ownership of channel %s"), channel.Name()))
	case errChannelTransferNotOffered:
		service.Notice(rb, fmt.Sprintf(client.t("You weren't offered ownership of channel %s"), channel.Name()))
	default:
		service.Notice(rb, fmt.Sprintf(client.t("Could not accept ownership of channel %s"), channel.Name()))
	}
}

func csPurgeHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	oper := client.Oper()
	if oper == nil {
		return // should be impossible because you need oper capabs for this
	}

	switch strings.ToLower(params[0]) {
	case "add":
		csPurgeAddHandler(service, client, params[1:], oper.Name, rb)
	case "del", "remove":
		csPurgeDelHandler(service, client, params[1:], oper.Name, rb)
	case "list":
		csPurgeListHandler(service, client, rb)
	default:
		service.Notice(rb, client.t("Invalid parameters"))
	}
}

func csPurgeAddHandler(service *ircService, client *Client, params []string, operName string, rb *ResponseBuffer) {
	if len(params) == 0 {
		service.Notice(rb, client.t("Invalid parameters"))
		return
	}

	chname := params[0]
	params = params[1:]
	channel := client.server.channels.Get(chname) // possibly nil
	var ctime time.Time
	if channel != nil {
		chname = channel.Name()
		ctime = channel.Ctime()
	}
	code := utils.ConfirmationCode(chname, ctime)

	if len(params) == 0 || params[0] != code {
		service.Notice(rb, ircfmt.Unescape(client.t("$bWarning: you are about to empty this channel and remove it from the server.$b")))
		service.Notice(rb, fmt.Sprintf(client.t("To confirm, run this command: %s"), fmt.Sprintf("/CS PURGE ADD %s %s", chname, code)))
		return
	}
	params = params[1:]

	var reason string
	if 1 < len(params) {
		reason = params[1]
	}

	purgeRecord := ChannelPurgeRecord{
		Oper:     operName,
		PurgedAt: time.Now().UTC(),
		Reason:   reason,
	}
	switch client.server.channels.Purge(chname, purgeRecord) {
	case nil:
		if channel != nil { // channel need not exist to be purged
			for _, target := range channel.Members() {
				channel.Kick(client, target, "Cleared by ChanServ", rb, true)
			}
		}
		service.Notice(rb, fmt.Sprintf(client.t("Successfully purged channel %s from the server"), chname))
		client.server.snomasks.Send(sno.LocalChannels, fmt.Sprintf("Operator %s purged channel %s [reason: %s]", operName, chname, reason))
	case errInvalidChannelName:
		service.Notice(rb, fmt.Sprintf(client.t("Can't purge invalid channel %s"), chname))
	default:
		service.Notice(rb, client.t("An error occurred"))
	}
}

func csPurgeDelHandler(service *ircService, client *Client, params []string, operName string, rb *ResponseBuffer) {
	if len(params) == 0 {
		service.Notice(rb, client.t("Invalid parameters"))
		return
	}

	chname := params[0]
	switch client.server.channels.Unpurge(chname) {
	case nil:
		service.Notice(rb, fmt.Sprintf(client.t("Successfully unpurged channel %s from the server"), chname))
		client.server.snomasks.Send(sno.LocalChannels, fmt.Sprintf("Operator %s removed purge of channel %s", operName, chname))
	case errNoSuchChannel:
		service.Notice(rb, fmt.Sprintf(client.t("Channel %s wasn't previously purged from the server"), chname))
	default:
		service.Notice(rb, client.t("An error occurred"))
	}
}

func csPurgeListHandler(service *ircService, client *Client, rb *ResponseBuffer) {
	l := client.server.channels.ListPurged()
	service.Notice(rb, fmt.Sprintf(client.t("There are %d purged channel(s)."), len(l)))
	for i, c := range l {
		service.Notice(rb, fmt.Sprintf("%d: %s", i+1, c))
	}
}

func csListHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	if !client.HasRoleCapabs("chanreg") {
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

	service.Notice(rb, ircfmt.Unescape(client.t("*** $bChanServ LIST$b ***")))

	channels := server.channelRegistry.AllChannels()
	for _, channel := range channels {
		if searchRegex == nil || searchRegex.MatchString(channel) {
			service.Notice(rb, fmt.Sprintf("    %s", channel))
		}
	}

	service.Notice(rb, ircfmt.Unescape(client.t("*** $bEnd of ChanServ LIST$b ***")))
}

func csInfoHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	if len(params) == 0 {
		// #765
		listRegisteredChannels(service, client.Account(), rb)
		return
	}

	chname, err := CasefoldChannel(params[0])
	if err != nil {
		service.Notice(rb, client.t("Invalid channel name"))
		return
	}

	// purge status
	if client.HasRoleCapabs("chanreg") {
		purgeRecord, err := server.channelRegistry.LoadPurgeRecord(chname)
		if err == nil {
			service.Notice(rb, fmt.Sprintf(client.t("Channel %s was purged by the server operators and cannot be used"), chname))
			service.Notice(rb, fmt.Sprintf(client.t("Purged by operator: %s"), purgeRecord.Oper))
			service.Notice(rb, fmt.Sprintf(client.t("Purged at: %s"), purgeRecord.PurgedAt.Format(time.RFC1123)))
			if purgeRecord.Reason != "" {
				service.Notice(rb, fmt.Sprintf(client.t("Purge reason: %s"), purgeRecord.Reason))
			}
		}
	} else {
		if server.channels.IsPurged(chname) {
			service.Notice(rb, fmt.Sprintf(client.t("Channel %s was purged by the server operators and cannot be used"), chname))
		}
	}

	var chinfo RegisteredChannel
	channel := server.channels.Get(params[0])
	if channel != nil {
		chinfo = channel.ExportRegistration(0)
	} else {
		chinfo, err = server.channelRegistry.LoadChannel(chname)
		if err != nil && !(err == errNoSuchChannel || err == errFeatureDisabled) {
			service.Notice(rb, client.t("An error occurred"))
			return
		}
	}

	// channel exists but is unregistered, or doesn't exist:
	if chinfo.Founder == "" {
		service.Notice(rb, fmt.Sprintf(client.t("Channel %s is not registered"), chname))
		return
	}
	service.Notice(rb, fmt.Sprintf(client.t("Channel %s is registered"), chinfo.Name))
	service.Notice(rb, fmt.Sprintf(client.t("Founder: %s"), chinfo.Founder))
	service.Notice(rb, fmt.Sprintf(client.t("Registered at: %s"), chinfo.RegisteredAt.Format(time.RFC1123)))
}

func displayChannelSetting(service *ircService, settingName string, settings ChannelSettings, client *Client, rb *ResponseBuffer) {
	config := client.server.Config()

	switch strings.ToLower(settingName) {
	case "history":
		effectiveValue := historyEnabled(config.History.Persistent.RegisteredChannels, settings.History)
		service.Notice(rb, fmt.Sprintf(client.t("The stored channel history setting is: %s"), historyStatusToString(settings.History)))
		service.Notice(rb, fmt.Sprintf(client.t("Given current server settings, the channel history setting is: %s"), historyStatusToString(effectiveValue)))
	case "query-cutoff":
		effectiveValue := settings.QueryCutoff
		if effectiveValue == HistoryCutoffDefault {
			effectiveValue = config.History.Restrictions.queryCutoff
		}
		service.Notice(rb, fmt.Sprintf(client.t("The stored channel history query cutoff setting is: %s"), historyCutoffToString(settings.QueryCutoff)))
		service.Notice(rb, fmt.Sprintf(client.t("Given current server settings, the channel history query cutoff setting is: %s"), historyCutoffToString(effectiveValue)))
	default:
		service.Notice(rb, client.t("Invalid params"))
	}
}

func csGetHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	chname, setting := params[0], params[1]
	channel := server.channels.Get(chname)
	if channel == nil {
		service.Notice(rb, client.t("No such channel"))
		return
	}
	info := channel.ExportRegistration(IncludeSettings)
	if !csPrivsCheck(service, info, client, rb) {
		return
	}

	displayChannelSetting(service, setting, info.Settings, client, rb)
}

func csSetHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	chname, setting, value := params[0], params[1], params[2]
	channel := server.channels.Get(chname)
	if channel == nil {
		service.Notice(rb, client.t("No such channel"))
		return
	}
	info := channel.ExportRegistration(IncludeSettings)
	settings := info.Settings
	if !csPrivsCheck(service, info, client, rb) {
		return
	}

	var err error
	switch strings.ToLower(setting) {
	case "history":
		settings.History, err = historyStatusFromString(value)
		if err != nil {
			err = errInvalidParams
			break
		}
		channel.SetSettings(settings)
		channel.resizeHistory(server.Config())
	case "query-cutoff":
		settings.QueryCutoff, err = historyCutoffFromString(value)
		if err != nil {
			err = errInvalidParams
			break
		}
		channel.SetSettings(settings)
	}

	switch err {
	case nil:
		service.Notice(rb, client.t("Successfully changed the channel settings"))
		displayChannelSetting(service, setting, settings, client, rb)
	case errInvalidParams:
		service.Notice(rb, client.t("Invalid parameters"))
	default:
		server.logger.Error("internal", "CS SET error:", err.Error())
		service.Notice(rb, client.t("An error occurred"))
	}
}

func csHowToBanHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	success := false
	defer func() {
		if success {
			service.Notice(rb, client.t("Note that if the user is currently in the channel, you must /KICK them after you ban them"))
		}
	}()

	chname, nick := params[0], params[1]
	channel := server.channels.Get(chname)
	if channel == nil {
		service.Notice(rb, client.t("No such channel"))
		return
	}

	if !(channel.ClientIsAtLeast(client, modes.ChannelOperator) || client.HasRoleCapabs("samode")) {
		service.Notice(rb, client.t("Insufficient privileges"))
		return
	}

	var details WhoWas
	target := server.clients.Get(nick)
	if target == nil {
		whowasList := server.whoWas.Find(nick, 1)
		if len(whowasList) == 0 {
			service.Notice(rb, client.t("No such nick"))
			return
		}
		service.Notice(rb, fmt.Sprintf(client.t("Warning: %s is not currently connected to the server. Using WHOWAS data, which may be inaccurate:"), nick))
		details = whowasList[0]
	} else {
		details = target.Details().WhoWas
	}

	if details.account != "" {
		if channel.getAmode(details.account) != modes.Mode(0) {
			service.Notice(rb, fmt.Sprintf(client.t("Warning: account %s currently has a persistent channel privilege granted with CS AMODE. If this mode is not removed, bans will not be respected"), details.accountName))
			return
		} else if details.account == channel.Founder() {
			service.Notice(rb, fmt.Sprintf(client.t("Warning: account %s is the channel founder and cannot be banned"), details.accountName))
			return
		}
	}

	config := server.Config()
	if !config.Server.Cloaks.EnabledForAlwaysOn {
		service.Notice(rb, client.t("Warning: server.ip-cloaking.enabled-for-always-on is disabled. This reduces the precision of channel bans."))
	}

	if details.account != "" {
		if config.Accounts.NickReservation.ForceNickEqualsAccount || target.AlwaysOn() {
			service.Notice(rb, fmt.Sprintf(client.t("User %[1]s is authenticated and can be banned by nickname: /MODE %[2]s +b %[3]s!*@*"), details.nick, channel.Name(), details.nick))
			success = true
			return
		}
	}

	ban := fmt.Sprintf("*!*@%s", strings.ToLower(details.hostname))
	banRe, err := utils.CompileGlob(ban, false)
	if err != nil {
		server.logger.Error("internal", "couldn't compile ban regex", ban, err.Error())
		service.Notice(rb, "An error occurred")
		return
	}
	var collateralDamage []string
	for _, mcl := range channel.Members() {
		if mcl != target && banRe.MatchString(mcl.NickMaskCasefolded()) {
			collateralDamage = append(collateralDamage, mcl.Nick())
		}
	}
	service.Notice(rb, fmt.Sprintf(client.t("User %[1]s can be banned by hostname: /MODE %[2]s +b %[3]s"), details.nick, channel.Name(), ban))
	success = true
	if len(collateralDamage) != 0 {
		service.Notice(rb, fmt.Sprintf(client.t("Warning: this ban will affect %d other users:"), len(collateralDamage)))
		for _, line := range utils.BuildTokenLines(400, collateralDamage, " ") {
			service.Notice(rb, line)
		}
	}
}
