// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"

	"github.com/oragono/oragono/irc/caps"
	"github.com/oragono/oragono/irc/modes"
)

const (
	npcNickMask   = "*%s*!%s@npc.fakeuser.invalid"
	sceneNickMask = "=Scene=!%s@npc.fakeuser.invalid"
)

func sendRoleplayMessage(server *Server, client *Client, source string, targetString string, isAction bool, message string, rb *ResponseBuffer) {
	if isAction {
		message = fmt.Sprintf("\x01ACTION %s (%s)\x01", message, client.nick)
	} else {
		// block attempts to send CTCP messages to Tor clients
		// TODO(#395) clean this up
		if len(message) != 0 && message[0] == '\x01' {
			return
		}
		message = fmt.Sprintf("%s (%s)", message, client.nick)
	}

	target, cerr := CasefoldChannel(targetString)
	if cerr == nil {
		channel := server.channels.Get(target)
		if channel == nil {
			rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, targetString, client.t("No such channel"))
			return
		}

		if !channel.CanSpeak(client) {
			rb.Add(nil, client.server.name, ERR_CANNOTSENDTOCHAN, channel.name, client.t("Cannot send to channel"))
			return
		}

		if !channel.flags.HasMode(modes.ChanRoleplaying) {
			rb.Add(nil, client.server.name, ERR_CANNOTSENDRP, channel.name, client.t("Channel doesn't have roleplaying mode available"))
			return
		}

		for _, member := range channel.Members() {
			for _, session := range member.Sessions() {
				// see discussion on #865: clients do not understand how to do local echo
				// of roleplay commands, so send them a copy whether they have echo-message
				// or not
				if rb.session == session {
					rb.Add(nil, source, "PRIVMSG", channel.name, message)
				} else {
					session.Send(nil, source, "PRIVMSG", channel.name, message)
				}
			}
		}
	} else {
		target, err := CasefoldName(targetString)
		user := server.clients.Get(target)
		if err != nil || user == nil {
			rb.Add(nil, server.name, ERR_NOSUCHNICK, client.nick, target, client.t("No such nick"))
			return
		}

		if !user.HasMode(modes.UserRoleplaying) {
			rb.Add(nil, client.server.name, ERR_CANNOTSENDRP, user.nick, client.t("User doesn't have roleplaying mode enabled"))
			return
		}

		cnick := client.Nick()
		tnick := user.Nick()
		user.Send(nil, source, "PRIVMSG", tnick, message)
		if rb.session.capabilities.Has(caps.EchoMessage) {
			rb.Add(nil, source, "PRIVMSG", tnick, message)
		}
		if user.Away() {
			//TODO(dan): possibly implement cooldown of away notifications to users
			rb.Add(nil, server.name, RPL_AWAY, cnick, tnick, user.AwayMessage())
		}
	}
}
