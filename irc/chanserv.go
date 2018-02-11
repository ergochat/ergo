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
	} else {
		rb.ChanServNotice(client.t("Sorry, I don't know that command"))
	}
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
