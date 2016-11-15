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

	nicknameRaw := strings.TrimSpace(msg.Params[0])
	nickname, err := CasefoldName(nicknameRaw)

	if len(nicknameRaw) < 1 {
		client.Send(nil, server.name, ERR_NONICKNAMEGIVEN, client.nick, "No nickname given")
		return false
	}

	if err != nil || len(nicknameRaw) > server.limits.NickLen || nickname == "=scene=" {
		client.Send(nil, server.name, ERR_ERRONEUSNICKNAME, client.nick, nicknameRaw, "Erroneous nickname")
		return false
	}

	if client.nick == nickname {
		return false
	}

	// bleh, this will be replaced and done below
	target := server.clients.Get(nickname)
	if target != nil && target != client {
		client.Send(nil, server.name, ERR_NICKNAMEINUSE, client.nick, nicknameRaw, "Nickname is already in use")
		return false
	}
	if client.registered {
		err = client.ChangeNickname(nicknameRaw)
	} else {
		err = client.SetNickname(nicknameRaw)
	}
	if err != nil {
		client.Send(nil, server.name, ERR_NICKNAMEINUSE, client.nick, nicknameRaw, "Nickname is already in use")
		return false
	}
	if client.registered {
		client.alertMonitors()
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
	nickname, err := CasefoldName(msg.Params[1])

	if len(nickname) < 1 {
		client.Send(nil, server.name, ERR_NONICKNAMEGIVEN, client.nick, "No nickname given")
		return false
	}

	if oerr != nil || err != nil || len(strings.TrimSpace(msg.Params[1])) > server.limits.NickLen || nickname == "=scene=" {
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
	if server.clients.Get(nickname) != nil || server.clients.Get(nickname) != target {
		client.Send(nil, server.name, ERR_NICKNAMEINUSE, client.nick, msg.Params[0], "Nickname is already in use")
		return false
	}

	target.ChangeNickname(msg.Params[1])
	return false
}
