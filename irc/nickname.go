// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import "github.com/DanielOaks/girc-go/ircmsg"

// NICK <nickname>
func nickHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if !client.authorized {
		client.Quit("Bad password")
		return true
	}

	nickname := NewName(msg.Params[0])

	if len(nickname) < 1 {
		client.Send(nil, server.nameString, ERR_NONICKNAMEGIVEN, client.nickString, "No nickname given")
		return false
	}

	if !nickname.IsNickname() {
		client.Send(nil, server.nameString, ERR_ERRONEUSNICKNAME, client.nickString, msg.Params[0], "Erroneous nickname")
		return false
	}

	if client.nick == nickname {
		return false
	}

	//TODO(dan): There's probably some races here, we should be changing this in the primary server thread
	target := server.clients.Get(nickname)
	if target != nil && target != client {
		client.Send(nil, server.nameString, ERR_NICKNAMEINUSE, client.nickString, msg.Params[0], "Nickname is already in use")
		return false
	}

	client.SetNickname(nickname)
	server.tryRegister(client)
	return false
}

// SANICK <oldnick> <nickname>
func sanickHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if !client.authorized {
		client.Quit("Bad password")
		return true
	}

	oldnick := NewName(msg.Params[0])
	nickname := NewName(msg.Params[1])

	if len(nickname) < 1 {
		client.Send(nil, server.nameString, ERR_NONICKNAMEGIVEN, client.nickString, "No nickname given")
		return false
	}

	if !nickname.IsNickname() {
		client.Send(nil, server.nameString, ERR_ERRONEUSNICKNAME, client.nickString, msg.Params[0], "Erroneous nickname")
		return false
	}

	if client.nick == nickname {
		return false
	}

	target := server.clients.Get(oldnick)
	if target == nil {
		client.Send(nil, server.nameString, ERR_NOSUCHNICK, msg.Params[0], "No such nick")
		return false
	}

	//TODO(dan): There's probably some races here, we should be changing this in the primary server thread
	if server.clients.Get(nickname) != nil {
		client.Send(nil, server.nameString, ERR_NICKNAMEINUSE, client.nickString, msg.Params[0], "Nickname is already in use")
		return false
	}

	target.SetNickname(nickname)
	return false
}
