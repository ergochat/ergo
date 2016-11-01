// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"

	"github.com/DanielOaks/girc-go/ircmsg"
)

const (
	npcNickMask   = "*%s*!%s@npc.fakeuser.invalid"
	sceneNickMask = "=Scene=!%s@npc.fakeuser.invalid"
)

// SCENE <target> <text to be sent>
func sceneHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	target := msg.Params[0]
	message := msg.Params[1]
	sourceString := fmt.Sprintf(sceneNickMask, client.nick)

	sendRoleplayMessage(server, client, sourceString, target, false, message)

	return false
}

// NPC <target> <text to be sent>
func npcHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	target := msg.Params[0]
	fakeSource := msg.Params[1]
	message := msg.Params[2]

	_, err := CasefoldName(fakeSource)
	if err != nil {
		client.Send(nil, client.server.name, ERR_CANNOTSENDRP, target, "Fake source must be a valid nickname")
		return false
	}

	sourceString := fmt.Sprintf(npcNickMask, fakeSource, client.nick)

	sendRoleplayMessage(server, client, sourceString, target, false, message)

	return false
}

// NPCA <target> <text to be sent>
func npcaHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	target := msg.Params[0]
	fakeSource := msg.Params[1]
	message := msg.Params[2]
	sourceString := fmt.Sprintf(npcNickMask, fakeSource, client.nick)

	_, err := CasefoldName(fakeSource)
	if err != nil {
		client.Send(nil, client.server.name, ERR_CANNOTSENDRP, target, "Fake source must be a valid nickname")
		return false
	}

	sendRoleplayMessage(server, client, sourceString, target, true, message)

	return false
}

func sendRoleplayMessage(server *Server, client *Client, source string, targetString string, isAction bool, message string) {
	if isAction {
		message = fmt.Sprintf("\x01ACTION %s (%s)\x01", message, client.nick)
	} else {
		message = fmt.Sprintf("%s (%s)", message, client.nick)
	}

	target, cerr := CasefoldChannel(targetString)
	if cerr == nil {
		channel := server.channels.Get(target)
		if channel == nil {
			client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, targetString, "No such channel")
			return
		}

		if !channel.CanSpeak(client) {
			client.Send(nil, client.server.name, ERR_CANNOTSENDTOCHAN, channel.name, "Cannot send to channel")
			return
		}

		if !channel.flags[ChanRoleplaying] {
			client.Send(nil, client.server.name, ERR_CANNOTSENDRP, channel.name, "Channel doesn't have roleplaying mode available")
			return
		}

		for member := range channel.members {
			if member == client && !client.capabilities[EchoMessage] {
				continue
			}
			member.Send(nil, source, "PRIVMSG", channel.name, message)
		}
	} else {
		target, err := CasefoldName(targetString)
		user := server.clients.Get(target)
		if err != nil || user == nil {
			client.Send(nil, server.name, ERR_NOSUCHNICK, target, "No such nick")
			return
		}

		if !user.flags[UserRoleplaying] {
			client.Send(nil, client.server.name, ERR_CANNOTSENDRP, user.nick, "User doesn't have roleplaying mode enabled")
			return
		}

		user.Send(nil, source, "PRIVMSG", user.nick, message)
		if client.capabilities[EchoMessage] {
			client.Send(nil, source, "PRIVMSG", user.nick, message)
		}
		if user.flags[Away] {
			//TODO(dan): possibly implement cooldown of away notifications to users
			client.Send(nil, server.name, RPL_AWAY, user.nick, user.awayMessage)
		}
	}
}
