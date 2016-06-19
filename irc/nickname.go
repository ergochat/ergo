// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import "github.com/DanielOaks/girc-go/ircmsg"

// NICK <nickname>
func nickHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// check NICK validity
	// send NICK change to primary server thread for processing
	//   |-> ensure no other client exists with that nickname
	//TODO(dan): SET client.nickString APPROPRIATELY
	return true
}

/*
type NickCommand struct {
	BaseCommand
	nickname Name
}

func (m *NickCommand) HandleRegServer(s *Server) {
	client := m.Client()
	if !client.authorized {
		client.ErrPasswdMismatch()
		client.Quit("bad password")
		return
	}
	//TODO(dan): SET client.nickString APPROPRIATELY

	if m.nickname == "" {
		client.ErrNoNicknameGiven()
		return
	}

	if s.clients.Get(m.nickname) != nil {
		client.ErrNickNameInUse(m.nickname)
		return
	}

	if !m.nickname.IsNickname() {
		client.ErrErroneusNickname(m.nickname)
		return
	}

	client.SetNickname(m.nickname)
	s.tryRegister(client)
}

func (msg *NickCommand) HandleServer(server *Server) {
	client := msg.Client()
	//TODO(dan): SET client.nickString APPROPRIATELY

	if msg.nickname == "" {
		client.ErrNoNicknameGiven()
		return
	}

	if !msg.nickname.IsNickname() {
		client.ErrErroneusNickname(msg.nickname)
		return
	}

	if msg.nickname == client.nick {
		return
	}

	target := server.clients.Get(msg.nickname)
	if (target != nil) && (target != client) {
		client.ErrNickNameInUse(msg.nickname)
		return
	}

	client.ChangeNickname(msg.nickname)
}

type OperNickCommand struct {
	BaseCommand
	target Name
	nick   Name
}

func (msg *OperNickCommand) HandleServer(server *Server) {
	client := msg.Client()
	//TODO(dan): SET client.nickString APPROPRIATELY

	if !client.flags[Operator] {
		client.ErrNoPrivileges()
		return
	}

	if !msg.nick.IsNickname() {
		client.ErrErroneusNickname(msg.nick)
		return
	}

	if msg.nick == client.nick {
		return
	}

	target := server.clients.Get(msg.target)
	if target == nil {
		client.ErrNoSuchNick(msg.target)
		return
	}

	if server.clients.Get(msg.nick) != nil {
		client.ErrNickNameInUse(msg.nick)
		return
	}

	target.ChangeNickname(msg.nick)
}
*/
