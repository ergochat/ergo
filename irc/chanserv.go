// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"strings"

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/sno"
)

// ChanServNotice sends the client a notice from ChanServ.
func (rb *ResponseBuffer) ChanServNotice(text string) {
	rb.Add(nil, fmt.Sprintf("ChanServ!services@%s", rb.target.server.name), "NOTICE", rb.target.nick, text)
}

// chanservReceiveNotice handles NOTICEs that ChanServ receives.
func (server *Server) chanservNoticeHandler(client *Client, message string, rb *ResponseBuffer) {
	// do nothing
}

// chanservReceiveNotice handles NOTICEs that ChanServ receives.
func (server *Server) chanservPrivmsgHandler(client *Client, message string, rb *ResponseBuffer) {
	var params []string
	for _, p := range strings.Split(message, " ") {
		if len(p) > 0 {
			params = append(params, p)
		}
	}
	if len(params) < 1 {
		rb.ChanServNotice(client.t("You need to run a command"))
		//TODO(dan): dump CS help here
		return
	}

	command := strings.ToLower(params[0])
	server.logger.Debug("chanserv", fmt.Sprintf("Client %s ran command %s", client.nick, command))

	if command == "register" {
		if len(params) < 2 {
			rb.ChanServNotice(client.t("Syntax: REGISTER <channel>"))
			return
		}

		server.chanservRegisterHandler(client, params[1], rb)
	} else if command == "op" {
		if len(params) < 2 {
			rb.ChanServNotice(client.t("Syntax: OP <channel> [<nick>]"))
			return
		}

		var clientToOp string
		if 2 < len(params) {
			clientToOp = params[2]
		}

		server.chanservOpHandler(client, params[1], clientToOp, rb)
	} else {
		rb.ChanServNotice(client.t("Sorry, I don't know that command"))
	}
}

// chanservOpHandler handles the ChanServ OP subcommand.
func (server *Server) chanservOpHandler(client *Client, channelName, clientToOp string, rb *ResponseBuffer) {
	channelKey, err := CasefoldChannel(channelName)
	if err != nil {
		rb.ChanServNotice(client.t("Channel name is not valid"))
		return
	}

	channelInfo := server.channels.Get(channelKey)
	if channelInfo == nil {
		rb.ChanServNotice(client.t("Channel does not exist"))
		return
	}

	clientAccount := client.Account()

	if clientAccount == "" {
		rb.ChanServNotice(client.t("You must be logged in to op on a channel"))
		return
	}

	if clientAccount != channelInfo.Founder() {
		rb.ChanServNotice(client.t("You must be the channel founder to op"))
		return
	}

	var target *Client
	if clientToOp != "" {
		casefoldedNickname, err := CasefoldName(clientToOp)
		target = server.clients.Get(casefoldedNickname)
		if err != nil || target == nil {
			rb.ChanServNotice(client.t("Could not find given client"))
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
	change := channelInfo.applyModeMemberNoMutex(target, givenMode, modes.Add, client.NickCasefolded(), rb)
	if change != nil {
		//TODO(dan): we should change the name of String and make it return a slice here
		//TODO(dan): unify this code with code in modes.go
		args := append([]string{channelName}, strings.Split(change.String(), " ")...)
		for _, member := range channelInfo.Members() {
			member.Send(nil, fmt.Sprintf("ChanServ!services@%s", client.server.name), "MODE", args...)
		}
	}

	rb.ChanServNotice(fmt.Sprintf(client.t("Successfully op'd in channel %s"), channelName))

	server.logger.Info("chanserv", fmt.Sprintf("Client %s op'd [%s] in channel %s", client.nick, clientToOp, channelName))
	server.snomasks.Send(sno.LocalChannels, fmt.Sprintf(ircfmt.Unescape("Client $c[grey][$r%s$c[grey]] CS OP'd $c[grey][$r%s$c[grey]] in channel $c[grey][$r%s$c[grey]]"), client.nickMaskString, clientToOp, channelName))
}

// chanservRegisterHandler handles the ChanServ REGISTER subcommand.
func (server *Server) chanservRegisterHandler(client *Client, channelName string, rb *ResponseBuffer) {
	if !server.channelRegistrationEnabled {
		rb.ChanServNotice(client.t("Channel registration is not enabled"))
		return
	}

	channelKey, err := CasefoldChannel(channelName)
	if err != nil {
		rb.ChanServNotice(client.t("Channel name is not valid"))
		return
	}

	channelInfo := server.channels.Get(channelKey)
	if channelInfo == nil || !channelInfo.ClientIsAtLeast(client, modes.ChannelOperator) {
		rb.ChanServNotice(client.t("You must be an oper on the channel to register it"))
		return
	}

	if client.Account() == "" {
		rb.ChanServNotice(client.t("You must be logged in to register a channel"))
		return
	}

	// this provides the synchronization that allows exactly one registration of the channel:
	err = channelInfo.SetRegistered(client.Account())
	if err != nil {
		rb.ChanServNotice(err.Error())
		return
	}

	// registration was successful: make the database reflect it
	go server.channelRegistry.StoreChannel(channelInfo, true)

	rb.ChanServNotice(fmt.Sprintf(client.t("Channel %s successfully registered"), channelName))

	server.logger.Info("chanserv", fmt.Sprintf("Client %s registered channel %s", client.nick, channelName))
	server.snomasks.Send(sno.LocalChannels, fmt.Sprintf(ircfmt.Unescape("Channel registered $c[grey][$r%s$c[grey]] by $c[grey][$r%s$c[grey]]"), channelName, client.nickMaskString))

	// give them founder privs
	change := channelInfo.applyModeMemberNoMutex(client, modes.ChannelFounder, modes.Add, client.NickCasefolded(), rb)
	if change != nil {
		//TODO(dan): we should change the name of String and make it return a slice here
		//TODO(dan): unify this code with code in modes.go
		args := append([]string{channelName}, strings.Split(change.String(), " ")...)
		for _, member := range channelInfo.Members() {
			member.Send(nil, fmt.Sprintf("ChanServ!services@%s", client.server.name), "MODE", args...)
		}
	}
}
