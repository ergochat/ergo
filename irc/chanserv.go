// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"sort"
	"strings"

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

var (
	chanservCommands = map[string]*serviceCommand{
		"op": {
			handler: csOpHandler,
			help: `Syntax: $bOP #channel [nickname]$b

OP makes the given nickname, or yourself, a channel admin. You can only use
this command if you're the founder of the channel.`,
			helpShort:    `$bOP$b makes the given user (or yourself) a channel admin.`,
			authRequired: true,
		},
		"register": {
			handler: csRegisterHandler,
			help: `Syntax: $bREGISTER #channel$b

REGISTER lets you own the given channel. If you rejoin this channel, you'll be
given admin privs on it. Modes set on the channel and the topic will also be
remembered.`,
			helpShort:    `$bREGISTER$b lets you own a given channel.`,
			authRequired: true,
		},
		"amode": {
			handler: csAmodeHandler,
			help: `Syntax: $bAMODE #channel [mode change] [account]$b

AMODE lists or modifies persistent mode settings that affect channel members.
For example, $bAMODE #channel +o dan$b grants the the holder of the "dan"
account the +o operator mode every time they join #channel. To list current
accounts and modes, use $bAMODE #channel$b. Note that users are always
referenced by their registered account names, not their nicknames.`,
			helpShort:    `$bAMODE$b modifies persistent mode settings for channel members.`,
			authRequired: true,
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
	}

	clientAccount := client.Account()
	if clientAccount == "" || clientAccount != channel.Founder() {
		csNotice(rb, client.t("You must be the channel founder to use AMODE"))
		return
	}

	modeChanges, unknown := modes.ParseChannelModeChanges(strings.Fields(modeChange)...)

	if len(modeChanges) > 1 || len(unknown) > 0 {
		csNotice(rb, client.t("Invalid mode change"))
		return
	}

	if len(modeChanges) == 0 || modeChanges[0].Op == modes.List {
		persistentModes := channel.AccountToUmode()
		// sort the persistent modes in descending order of priority, i.e.,
		// ascending order of their index in the ChannelUserModes list
		sort.Slice(persistentModes, func(i, j int) bool {
			index := func(modeChange modes.ModeChange) int {
				for idx, mode := range modes.ChannelUserModes {
					if modeChange.Mode == mode {
						return idx
					}
				}
				return len(modes.ChannelUserModes)
			}
			return index(persistentModes[i]) < index(persistentModes[j])
		})
		csNotice(rb, fmt.Sprintf(client.t("Channel %s has %d persistent modes set"), channelName, len(persistentModes)))
		for _, modeChange := range persistentModes {
			csNotice(rb, fmt.Sprintf(client.t("Account %s receives mode +%s"), modeChange.Arg, string(modeChange.Mode)))
		}
		return
	}

	accountIsValid := false
	change := modeChanges[0]
	// Arg is the account name, casefold it here
	change.Arg, _ = CasefoldName(change.Arg)
	if change.Arg != "" {
		_, err := server.accounts.LoadAccount(change.Arg)
		accountIsValid = (err == nil)
	}
	if !accountIsValid {
		csNotice(rb, client.t("Account does not exist"))
		return
	}
	applied := channel.ApplyAccountToUmodeChange(change)
	if applied {
		csNotice(rb, fmt.Sprintf(client.t("Successfully set mode %s"), change.String()))
		go server.channelRegistry.StoreChannel(channel, IncludeLists)
	} else {
		csNotice(rb, client.t("Change was a no-op"))
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
	if !server.channelRegistrationEnabled {
		csNotice(rb, client.t("Channel registration is not enabled"))
		return
	}

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
