// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
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
	}
)

// csNotice sends the client a notice from ChanServ
func csNotice(rb *ResponseBuffer, text string) {
	rb.Add(nil, "ChanServ", "NOTICE", rb.target.Nick(), text)
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
