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
)

const chanservHelp = `ChanServ lets you register and manage channels.

To see in-depth help for a specific ChanServ command, try:
    $b/CS HELP <command>$b

Here are the commands you can use:
%s`

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
	}
)

// csNotice sends the client a notice from ChanServ
func csNotice(rb *ResponseBuffer, text string) {
	rb.Add(nil, "ChanServ!ChanServ@localhost", "NOTICE", rb.target.Nick(), text)
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
	channelsAlreadyRegistered := server.accounts.ChannelsForAccount(account)
	if server.Config().Channels.Registration.MaxChannelsPerAccount <= len(channelsAlreadyRegistered) {
		csNotice(rb, client.t("You have already registered the maximum number of channels; try dropping some with /CS UNREGISTER"))
		return
	}

	// this provides the synchronization that allows exactly one registration of the channel:
	err = server.channels.SetRegistered(channelKey, account)
	if err != nil {
		csNotice(rb, err.Error())
		return
	}

	csNotice(rb, fmt.Sprintf(client.t("Channel %s successfully registered"), channelName))

	server.logger.Info("services", fmt.Sprintf("Client %s registered channel %s", client.nick, channelName))
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
	expectedCode := unregisterConfirmationCode(info.Name, info.RegisteredAt)
	if expectedCode != verificationCode {
		csNotice(rb, ircfmt.Unescape(client.t("$bWarning: unregistering this channel will remove all stored channel attributes.$b")))
		csNotice(rb, fmt.Sprintf(client.t("To confirm channel unregistration, type: /CS UNREGISTER %[1]s %[2]s"), channelKey, expectedCode))
		return
	}

	server.channels.SetUnregistered(channelKey, founder)
	csNotice(rb, fmt.Sprintf(client.t("Channel %s is now unregistered"), channelKey))
}

// deterministically generates a confirmation code for unregistering a channel / account
func unregisterConfirmationCode(name string, registeredAt time.Time) (code string) {
	var codeInput bytes.Buffer
	codeInput.WriteString(name)
	codeInput.WriteString(strconv.FormatInt(registeredAt.Unix(), 16))
	return strconv.Itoa(int(crc32.ChecksumIEEE(codeInput.Bytes())))
}
