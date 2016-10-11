// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"strings"

	"github.com/DanielOaks/girc-go/ircmsg"
)

// NICK <nickname>
func nickHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if !client.authorized {
		client.Quit("Bad password")
		return true
	}

	nickname, err := CasefoldName(msg.Params[0])

	if len(strings.TrimSpace(msg.Params[0])) < 1 {
		client.Send(nil, server.name, ERR_NONICKNAMEGIVEN, client.nick, "No nickname given")
		return false
	}

	if err != nil || len(strings.TrimSpace(msg.Params[0])) > server.limits.NickLen {
		client.Send(nil, server.name, ERR_ERRONEUSNICKNAME, client.nick, msg.Params[0], "Erroneous nickname")
		return false
	}

	if client.nick == nickname {
		return false
	}

	//TODO(dan): There's probably some races here, we should be changing this in the primary server thread
	target := server.clients.Get(nickname)
	if target != nil && target != client {
		client.Send(nil, server.name, ERR_NICKNAMEINUSE, client.nick, msg.Params[0], "Nickname is already in use")
		return false
	}

	if client.registered {
		client.ChangeNickname(nickname)
	} else {
		client.SetNickname(nickname)
	}
	server.tryRegister(client)
	return false
}

// SANICK <oldnick> <nickname>
func sanickHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if !client.authorized {
		client.Quit("Bad password")
		return true
	}

	oldnick, oerr := CasefoldName(msg.Params[0])
	casefoldedNickname, err := CasefoldName(msg.Params[1])

	if len(casefoldedNickname) < 1 {
		client.Send(nil, server.name, ERR_NONICKNAMEGIVEN, client.nick, "No nickname given")
		return false
	}

	if oerr != nil || err != nil || len(strings.TrimSpace(msg.Params[1])) > server.limits.NickLen {
		client.Send(nil, server.name, ERR_ERRONEUSNICKNAME, client.nick, msg.Params[0], "Erroneous nickname")
		return false
	}

	if client.nick == msg.Params[1] {
		return false
	}

	target := server.clients.Get(oldnick)
	if target == nil {
		client.Send(nil, server.name, ERR_NOSUCHNICK, msg.Params[0], "No such nick")
		return false
	}

	//TODO(dan): There's probably some races here, we should be changing this in the primary server thread
	if server.clients.Get(casefoldedNickname) != nil || server.clients.Get(casefoldedNickname) != target {
		client.Send(nil, server.name, ERR_NICKNAMEINUSE, client.nick, msg.Params[0], "Nickname is already in use")
		return false
	}

	target.ChangeNickname(msg.Params[1])
	return false
}
