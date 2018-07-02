// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/sno"
	"github.com/oragono/oragono/irc/utils"
)

const chanservHelp = `ChanServ lets you register and manage channels.

To see in-depth help for a specific ChanServ command, try:
    $b/CS HELP <command>$b

Here are the commands you can use:
%s`

func chanregEnabled(server *Server) bool {
	return server.ChannelRegistrationEnabled()
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
		},
		"unregister": {
			handler: csUnregisterHandler,
			help: `Syntax: $bUNREGISTER #channel [code]$b

UNREGISTER deletes a channel registration, allowing someone else to claim it.
To prevent accidental unregistrations, a verification code is required;
invoking the command without a code will display the necessary code.`,
			helpShort: `$bUNREGISTER$b deletes a channel registration.`,
			enabled:   chanregEnabled,
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
		},
	}
)

// csNotice sends the client a notice from ChanServ
func csNotice(rb *ResponseBuffer, text string) {
	rb.Add(nil, "ChanServ", "NOTICE", rb.target.Nick(), text)
}

func csAmodeHandler(server *Server, client *Client, command, params string, rb *ResponseBuffer) {
	channelName, modeChange := utils.ExtractParam(params)

	channel := server.channels.Get(channelName)
	if channel == nil {
		csNotice(rb, client.t("Channel does not exist"))
		return
	} else if channel.Founder() == "" {
		csNotice(rb, client.t("Channel is not registered"))
		return
	}

	modeChanges, unknown := modes.ParseChannelModeChanges(strings.Fields(modeChange)...)
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
		csNotice(rb, fmt.Sprintf(client.t("Channel %s has %d persistent modes set"), channelName, len(affectedModes)))
		for _, modeChange := range affectedModes {
			csNotice(rb, fmt.Sprintf(client.t("Account %s receives mode +%s"), modeChange.Arg, string(modeChange.Mode)))
		}
	case modes.Add, modes.Remove:
		if len(affectedModes) > 0 {
			csNotice(rb, fmt.Sprintf(client.t("Successfully set mode %s"), change.String()))
		} else {
			csNotice(rb, client.t("Change was a no-op"))
		}
	}
}

func csOpHandler(server *Server, client *Client, command, params string, rb *ResponseBuffer) {
	channelName, clientToOp := utils.ExtractParam(params)

	if channelName == "" {
		csNotice(rb, ircfmt.Unescape(client.t("Syntax: $bOP #channel [nickname]$b")))
		return
	}

	clientToOp = strings.TrimSpace(clientToOp)

	channelKey, err := CasefoldChannel(channelName)
	if err != nil {
		csNotice(rb, client.t("Channel name is not valid"))
		return
	}

	channelInfo := server.channels.Get(channelKey)
	if channelInfo == nil {
		csNotice(rb, client.t("Channel does not exist"))
		return
	}

	clientAccount := client.Account()
	if clientAccount == "" || clientAccount != channelInfo.Founder() {
		csNotice(rb, client.t("You must be the channel founder to op"))
		return
	}

	var target *Client
	if clientToOp != "" {
		casefoldedNickname, err := CasefoldName(clientToOp)
		target = server.clients.Get(casefoldedNickname)
		if err != nil || target == nil {
			csNotice(rb, client.t("Could not find given client"))
			return
		}
	} else {
		target = client
	}

	// give them privs
	givenMode := modes.ChannelOperator
	if client == target {
		givenMode = modes.ChannelFounder
	}
	change := channelInfo.applyModeToMember(target, givenMode, modes.Add, client.NickCasefolded(), rb)
	if change != nil {
		//TODO(dan): we should change the name of String and make it return a slice here
		//TODO(dan): unify this code with code in modes.go
		args := append([]string{channelName}, strings.Split(change.String(), " ")...)
		for _, member := range channelInfo.Members() {
			member.Send(nil, fmt.Sprintf("ChanServ!services@%s", client.server.name), "MODE", args...)
		}
	}

	csNotice(rb, fmt.Sprintf(client.t("Successfully op'd in channel %s"), channelName))

	server.logger.Info("chanserv", fmt.Sprintf("Client %s op'd [%s] in channel %s", client.nick, clientToOp, channelName))
	server.snomasks.Send(sno.LocalChannels, fmt.Sprintf(ircfmt.Unescape("Client $c[grey][$r%s$c[grey]] CS OP'd $c[grey][$r%s$c[grey]] in channel $c[grey][$r%s$c[grey]]"), client.nickMaskString, clientToOp, channelName))
}

func csRegisterHandler(server *Server, client *Client, command, params string, rb *ResponseBuffer) {
	channelName := strings.TrimSpace(params)
	if channelName == "" {
		csNotice(rb, ircfmt.Unescape(client.t("Syntax: $bREGISTER #channel$b")))
		return
	}

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

	// this provides the synchronization that allows exactly one registration of the channel:
	err = channelInfo.SetRegistered(client.Account())
	if err != nil {
		csNotice(rb, err.Error())
		return
	}

	// registration was successful: make the database reflect it
	go server.channelRegistry.StoreChannel(channelInfo, IncludeAllChannelAttrs)

	csNotice(rb, fmt.Sprintf(client.t("Channel %s successfully registered"), channelName))

	server.logger.Info("chanserv", fmt.Sprintf("Client %s registered channel %s", client.nick, channelName))
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

func csUnregisterHandler(server *Server, client *Client, command, params string, rb *ResponseBuffer) {
	channelName, verificationCode := utils.ExtractParam(params)
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

	hasPrivs := client.HasRoleCapabs("chanreg")
	if !hasPrivs {
		founder := channel.Founder()
		hasPrivs = founder != "" && founder == client.Account()
	}
	if !hasPrivs {
		csNotice(rb, client.t("Insufficient privileges"))
		return
	}

	info := channel.ExportRegistration(0)
	expectedCode := unregisterConfirmationCode(info.Name, info.RegisteredAt)
	if expectedCode != verificationCode {
		csNotice(rb, ircfmt.Unescape(client.t("$bWarning: unregistering this channel will remove all stored channel attributes.$b")))
		csNotice(rb, fmt.Sprintf(client.t("To confirm channel unregistration, type: /CS UNREGISTER %s %s"), channelKey, expectedCode))
		return
	}

	channel.SetUnregistered()
	go server.channelRegistry.Delete(channelKey, info)
	csNotice(rb, fmt.Sprintf(client.t("Channel %s is now unregistered"), channelKey))
}

// deterministically generates a confirmation code for unregistering a channel / account
func unregisterConfirmationCode(name string, registeredAt time.Time) (code string) {
	var codeInput bytes.Buffer
	codeInput.WriteString(name)
	codeInput.WriteString(strconv.FormatInt(registeredAt.Unix(), 16))
	return strconv.Itoa(int(crc32.ChecksumIEEE(codeInput.Bytes())))
}
