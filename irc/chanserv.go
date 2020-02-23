// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/sno"
	"github.com/oragono/oragono/irc/utils"
)

const chanservHelp = `ChanServ lets you register and manage channels.`
const chanservMask = "ChanServ!ChanServ@localhost"

func chanregEnabled(config *Config) bool {
	return config.Channels.Registration.Enabled
}

var (
	chanservCommands = map[string]*serviceCommand{
		"op": {
			handler: csOpHandler,
			help: `Syntax: $bOP #channel [nickname]$b

OP makes the given nickname, or yourself, a channel admin. You can only use
this command if you're the founder of the channel.`,
			helpShort:    `$bOP$b makes the given user (or yourself) a channel admin.`,
			authRequired: true,
			enabled:      chanregEnabled,
			minParams:    1,
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
For example, $bAMODE #channel +o dan$b grants the the holder of the "dan"
account the +o operator mode every time they join #channel. To list current
accounts and modes, use $bAMODE #channel$b. Note that users are always
referenced by their registered account names, not their nicknames.`,
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
			help: `Syntax: $bPURGE #channel [reason]$b

PURGE blacklists a channel from the server, making it impossible to join
or otherwise interact with the channel. If the channel currently has members,
they will be kicked from it. PURGE may also be applied preemptively to
channels that do not currently have members.`,
			helpShort:         `$bPURGE$b blacklists a channel from the server.`,
			capabs:            []string{"chanreg"},
			minParams:         1,
			maxParams:         2,
			unsplitFinalParam: true,
		},
		"unpurge": {
			handler: csUnpurgeHandler,
			help: `Syntax: $bUNPURGE #channel$b

UNPURGE removes any blacklisting of a channel that was previously
set using PURGE.`,
			helpShort: `$bUNPURGE$b undoes a previous PURGE command.`,
			capabs:    []string{"chanreg"},
			minParams: 1,
		},
		"info": {
			handler: csInfoHandler,
			help: `Syntax: $INFO #channel$b

INFO displays info about a registered channel.`,
			helpShort: `$bINFO$b displays info about a registered channel.`,
			enabled:   chanregEnabled,
			minParams: 1,
		},
	}
)

// csNotice sends the client a notice from ChanServ
func csNotice(rb *ResponseBuffer, text string) {
	rb.Add(nil, chanservMask, "NOTICE", rb.target.Nick(), text)
}

func csAmodeHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	channelName := params[0]

	channel := server.channels.Get(channelName)
	if channel == nil {
		csNotice(rb, client.t("Channel does not exist"))
		return
	} else if channel.Founder() == "" {
		csNotice(rb, client.t("Channel is not registered"))
		return
	}

	modeChanges, unknown := modes.ParseChannelModeChanges(params[1:]...)
	var change modes.ModeChange
	if len(modeChanges) > 1 || len(unknown) > 0 {
		csNotice(rb, client.t("Invalid mode change"))
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
		csNotice(rb, client.t("Account does not exist"))
		return
	}

	affectedModes, err := channel.ProcessAccountToUmodeChange(client, change)

	if err == errInsufficientPrivs {
		csNotice(rb, client.t("Insufficient privileges"))
		return
	} else if err != nil {
		csNotice(rb, client.t("Internal error"))
		return
	}

	switch change.Op {
	case modes.List:
		// sort the persistent modes in descending order of priority
		sort.Slice(affectedModes, func(i, j int) bool {
			return umodeGreaterThan(affectedModes[i].Mode, affectedModes[j].Mode)
		})
		csNotice(rb, fmt.Sprintf(client.t("Channel %[1]s has %[2]d persistent modes set"), channelName, len(affectedModes)))
		for _, modeChange := range affectedModes {
			csNotice(rb, fmt.Sprintf(client.t("Account %[1]s receives mode +%[2]s"), modeChange.Arg, string(modeChange.Mode)))
		}
	case modes.Add, modes.Remove:
		if len(affectedModes) > 0 {
			csNotice(rb, fmt.Sprintf(client.t("Successfully set mode %s"), change.String()))
		} else {
			csNotice(rb, client.t("No changes were made"))
		}
	}
}

func csOpHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	channelInfo := server.channels.Get(params[0])
	if channelInfo == nil {
		csNotice(rb, client.t("Channel does not exist"))
		return
	}
	channelName := channelInfo.Name()

	clientAccount := client.Account()
	if clientAccount == "" || clientAccount != channelInfo.Founder() {
		csNotice(rb, client.t("Only the channel founder can do this"))
		return
	}

	var target *Client
	if len(params) > 1 {
		target = server.clients.Get(params[1])
		if target == nil {
			csNotice(rb, client.t("Could not find given client"))
			return
		}
	} else {
		target = client
	}

	// give them privs
	givenMode := modes.ChannelOperator
	if clientAccount == target.Account() {
		givenMode = modes.ChannelFounder
	}
	change := channelInfo.applyModeToMember(client, givenMode, modes.Add, target.NickCasefolded(), rb)
	if change != nil {
		//TODO(dan): we should change the name of String and make it return a slice here
		//TODO(dan): unify this code with code in modes.go
		args := append([]string{channelName}, strings.Split(change.String(), " ")...)
		for _, member := range channelInfo.Members() {
			member.Send(nil, fmt.Sprintf("ChanServ!services@%s", client.server.name), "MODE", args...)
		}
	}

	csNotice(rb, fmt.Sprintf(client.t("Successfully op'd in channel %s"), channelName))

	tnick := target.Nick()
	server.logger.Info("services", fmt.Sprintf("Client %s op'd [%s] in channel %s", client.Nick(), tnick, channelName))
	server.snomasks.Send(sno.LocalChannels, fmt.Sprintf(ircfmt.Unescape("Client $c[grey][$r%s$c[grey]] CS OP'd $c[grey][$r%s$c[grey]] in channel $c[grey][$r%s$c[grey]]"), client.NickMaskString(), tnick, channelName))
}

func csRegisterHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	channelName := params[0]

	channelKey, err := CasefoldChannel(channelName)
	if err != nil {
		csNotice(rb, client.t("Channel name is not valid"))
		return
	}

	channelInfo := server.channels.Get(channelKey)
	if channelInfo == nil || !channelInfo.ClientIsAtLeast(client, modes.ChannelOperator) {
		csNotice(rb, client.t("You must be an oper on the channel to register it"))
		return
	}

	account := client.Account()
	if !checkChanLimit(client, rb) {
		return
	}

	// this provides the synchronization that allows exactly one registration of the channel:
	err = server.channels.SetRegistered(channelKey, account)
	if err != nil {
		csNotice(rb, err.Error())
		return
	}

	csNotice(rb, fmt.Sprintf(client.t("Channel %s successfully registered"), channelName))

	server.logger.Info("services", fmt.Sprintf("Client %s registered channel %s", client.Nick(), channelName))
	server.snomasks.Send(sno.LocalChannels, fmt.Sprintf(ircfmt.Unescape("Channel registered $c[grey][$r%s$c[grey]] by $c[grey][$r%s$c[grey]]"), channelName, client.nickMaskString))

	// give them founder privs
	change := channelInfo.applyModeToMember(client, modes.ChannelFounder, modes.Add, client.NickCasefolded(), rb)
	if change != nil {
		//TODO(dan): we should change the name of String and make it return a slice here
		//TODO(dan): unify this code with code in modes.go
		args := append([]string{channelName}, strings.Split(change.String(), " ")...)
		for _, member := range channelInfo.Members() {
			member.Send(nil, fmt.Sprintf("ChanServ!services@%s", client.server.name), "MODE", args...)
		}
	}
}

// check whether a client has already registered too many channels
func checkChanLimit(client *Client, rb *ResponseBuffer) (ok bool) {
	account := client.Account()
	channelsAlreadyRegistered := client.server.accounts.ChannelsForAccount(account)
	ok = len(channelsAlreadyRegistered) < client.server.Config().Channels.Registration.MaxChannelsPerAccount || client.HasRoleCapabs("chanreg")
	if !ok {
		csNotice(rb, client.t("You have already registered the maximum number of channels; try dropping some with /CS UNREGISTER"))
	}
	return
}

func csUnregisterHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	channelName := params[0]
	var verificationCode string
	if len(params) > 1 {
		verificationCode = params[1]
	}

	channelKey, err := CasefoldChannel(channelName)
	if channelKey == "" || err != nil {
		csNotice(rb, client.t("Channel name is not valid"))
		return
	}

	channel := server.channels.Get(channelKey)
	if channel == nil {
		csNotice(rb, client.t("No such channel"))
		return
	}

	founder := channel.Founder()
	if founder == "" {
		csNotice(rb, client.t("That channel is not registered"))
		return
	}

	hasPrivs := client.HasRoleCapabs("chanreg") || founder == client.Account()
	if !hasPrivs {
		csNotice(rb, client.t("Insufficient privileges"))
		return
	}

	info := channel.ExportRegistration(0)
	expectedCode := utils.ConfirmationCode(info.Name, info.RegisteredAt)
	if expectedCode != verificationCode {
		csNotice(rb, ircfmt.Unescape(client.t("$bWarning: unregistering this channel will remove all stored channel attributes.$b")))
		csNotice(rb, fmt.Sprintf(client.t("To confirm channel unregistration, type: /CS UNREGISTER %[1]s %[2]s"), channelKey, expectedCode))
		return
	}

	server.channels.SetUnregistered(channelKey, founder)
	csNotice(rb, fmt.Sprintf(client.t("Channel %s is now unregistered"), channelKey))
}

func csClearHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	channel := server.channels.Get(params[0])
	if channel == nil {
		csNotice(rb, client.t("Channel does not exist"))
		return
	}
	account := client.Account()
	if !(client.HasRoleCapabs("chanreg") || (account != "" && account == channel.Founder())) {
		csNotice(rb, client.t("Insufficient privileges"))
		return
	}

	switch strings.ToLower(params[1]) {
	case "access":
		channel.resetAccess()
		csNotice(rb, client.t("Successfully reset channel access"))
	case "users":
		for _, target := range channel.Members() {
			if target != client {
				channel.Kick(client, target, "Cleared by ChanServ", rb, true)
			}
		}
	default:
		csNotice(rb, client.t("Invalid parameters"))
	}

}

func csTransferHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	if strings.ToLower(params[0]) == "accept" {
		processTransferAccept(client, params[1], rb)
		return
	}
	chname := params[0]
	channel := server.channels.Get(chname)
	if channel == nil {
		csNotice(rb, client.t("Channel does not exist"))
		return
	}
	regInfo := channel.ExportRegistration(0)
	chname = regInfo.Name
	account := client.Account()
	isFounder := account != "" && account == regInfo.Founder
	hasPrivs := client.HasRoleCapabs("chanreg")
	if !(isFounder || hasPrivs) {
		csNotice(rb, client.t("Insufficient privileges"))
		return
	}
	target := params[1]
	targetAccount, err := server.accounts.LoadAccount(params[1])
	if err != nil {
		csNotice(rb, client.t("Account does not exist"))
		return
	}
	if targetAccount.NameCasefolded != account {
		expectedCode := utils.ConfirmationCode(regInfo.Name, regInfo.RegisteredAt)
		codeValidated := 2 < len(params) && params[2] == expectedCode
		if !codeValidated {
			csNotice(rb, ircfmt.Unescape(client.t("$bWarning: you are about to transfer control of your channel to another user.$b")))
			csNotice(rb, fmt.Sprintf(client.t("To confirm your channel transfer, type: /CS TRANSFER %[1]s %[2]s %[3]s"), chname, target, expectedCode))
			return
		}
	}
	status, err := channel.Transfer(client, target, hasPrivs)
	if err == nil {
		switch status {
		case channelTransferComplete:
			csNotice(rb, fmt.Sprintf(client.t("Successfully transferred channel %[1]s to account %[2]s"), chname, target))
		case channelTransferPending:
			sendTransferPendingNotice(server, target, chname)
			csNotice(rb, fmt.Sprintf(client.t("Transfer of channel %[1]s to account %[2]s succeeded, pending acceptance"), chname, target))
		case channelTransferCancelled:
			csNotice(rb, fmt.Sprintf(client.t("Cancelled pending transfer of channel %s"), chname))
		}
	} else {
		csNotice(rb, client.t("Could not transfer channel"))
	}
}

func sendTransferPendingNotice(server *Server, account, chname string) {
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
	client.Send(nil, chanservMask, "NOTICE", client.Nick(), fmt.Sprintf(client.t("You have been offered ownership of channel %[1]s. To accept, /CS TRANSFER ACCEPT %[1]s"), chname))
}

func processTransferAccept(client *Client, chname string, rb *ResponseBuffer) {
	channel := client.server.channels.Get(chname)
	if channel == nil {
		csNotice(rb, client.t("Channel does not exist"))
		return
	}
	if !checkChanLimit(client, rb) {
		return
	}
	switch channel.AcceptTransfer(client) {
	case nil:
		csNotice(rb, fmt.Sprintf(client.t("Successfully accepted ownership of channel %s"), channel.Name()))
	case errChannelTransferNotOffered:
		csNotice(rb, fmt.Sprintf(client.t("You weren't offered ownership of channel %s"), channel.Name()))
	default:
		csNotice(rb, fmt.Sprintf(client.t("Could not accept ownership of channel %s"), channel.Name()))
	}
}

func csPurgeHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	oper := client.Oper()
	if oper == nil {
		return // should be impossible because you need oper capabs for this
	}

	chname := params[0]
	var reason string
	if 1 < len(params) {
		reason = params[1]
	}
	purgeRecord := ChannelPurgeRecord{
		Oper:     oper.Name,
		PurgedAt: time.Now().UTC(),
		Reason:   reason,
	}
	switch server.channels.Purge(chname, purgeRecord) {
	case nil:
		channel := server.channels.Get(chname)
		if channel != nil { // channel need not exist to be purged
			for _, target := range channel.Members() {
				channel.Kick(client, target, "Cleared by ChanServ", rb, true)
			}
		}
		csNotice(rb, fmt.Sprintf(client.t("Successfully purged channel %s from the server"), chname))
	case errInvalidChannelName:
		csNotice(rb, fmt.Sprintf(client.t("Can't purge invalid channel %s"), chname))
	default:
		csNotice(rb, client.t("An error occurred"))
	}
}

func csUnpurgeHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	chname := params[0]
	switch server.channels.Unpurge(chname) {
	case nil:
		csNotice(rb, fmt.Sprintf(client.t("Successfully unpurged channel %s from the server"), chname))
	case errNoSuchChannel:
		csNotice(rb, fmt.Sprintf(client.t("Channel %s wasn't previously purged from the server"), chname))
	default:
		csNotice(rb, client.t("An error occurred"))
	}
}

func csInfoHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	chname, err := CasefoldChannel(params[0])
	if err != nil {
		csNotice(rb, client.t("Invalid channel name"))
		return
	}

	// purge status
	if client.HasRoleCapabs("chanreg") {
		purgeRecord, err := server.channelRegistry.LoadPurgeRecord(chname)
		if err == nil {
			csNotice(rb, fmt.Sprintf(client.t("Channel %s was purged by the server operators and cannot be used"), chname))
			csNotice(rb, fmt.Sprintf(client.t("Purged by operator: %s"), purgeRecord.Oper))
			csNotice(rb, fmt.Sprintf(client.t("Purged at: %s"), purgeRecord.PurgedAt.Format(time.RFC1123)))
			if purgeRecord.Reason != "" {
				csNotice(rb, fmt.Sprintf(client.t("Purge reason: %s"), purgeRecord.Reason))
			}
		}
	} else {
		if server.channels.IsPurged(chname) {
			csNotice(rb, fmt.Sprintf(client.t("Channel %s was purged by the server operators and cannot be used"), chname))
		}
	}

	var chinfo RegisteredChannel
	channel := server.channels.Get(params[0])
	if channel != nil {
		chinfo = channel.ExportRegistration(0)
	} else {
		chinfo, err = server.channelRegistry.LoadChannel(chname)
		if err != nil && !(err == errNoSuchChannel || err == errFeatureDisabled) {
			csNotice(rb, client.t("An error occurred"))
			return
		}
	}

	// channel exists but is unregistered, or doesn't exist:
	if chinfo.Founder == "" {
		csNotice(rb, fmt.Sprintf(client.t("Channel %s is not registered"), chname))
		return
	}
	csNotice(rb, fmt.Sprintf(client.t("Channel %s is registered"), chinfo.Name))
	csNotice(rb, fmt.Sprintf(client.t("Founder: %s"), chinfo.Founder))
	csNotice(rb, fmt.Sprintf(client.t("Registered at: %s"), chinfo.RegisteredAt.Format(time.RFC1123)))
}
