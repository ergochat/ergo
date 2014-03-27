package irc

import (
	"fmt"
)

type TheaterClient Name

func (c TheaterClient) Id() Name {
	return Name(c)
}

func (c TheaterClient) Nick() Name {
	return Name(c)
}

type TheaterSubCommand string

type theaterSubCommand interface {
	String() string
}

type TheaterIdentifyCommand struct {
	PassCommand
	channel Name
}

func (m *TheaterIdentifyCommand) LoadPassword(s *Server) {
	m.hash = s.theaters[m.channel]
}

func (cmd *TheaterIdentifyCommand) String() string {
	return fmt.Sprintf("THEATER_IDENTIFY(channel=%s)", cmd.channel)
}

func (m *TheaterIdentifyCommand) HandleServer(s *Server) {
	client := m.Client()
	if !m.channel.IsChannel() {
		client.ErrNoSuchChannel(m.channel)
		return
	}

	channel := s.channels.Get(m.channel)
	if channel == nil {
		client.ErrNoSuchChannel(m.channel)
		return
	}

	if (m.hash == nil) || (m.err != nil) {
		client.ErrPasswdMismatch()
		return
	}

	if channel.members.AnyHasMode(Theater) {
		client.Reply(RplNotice(s, client, "someone else is +T in this channel"))
		return
	}

	channel.members[client][Theater] = true
}

type TheaterPrivMsgCommand struct {
	BaseCommand
	channel Name
	asNick  Name
	message Text
}

func (cmd *TheaterPrivMsgCommand) String() string {
	return fmt.Sprintf("THEATER_PRIVMSG(channel=%s, asNick=%s, message=%s)", cmd.channel, cmd.asNick, cmd.message)

}
func (m *TheaterPrivMsgCommand) HandleServer(s *Server) {
	client := m.Client()

	if !m.channel.IsChannel() {
		client.ErrNoSuchChannel(m.channel)
		return
	}

	channel := s.channels.Get(m.channel)
	if channel == nil {
		client.ErrNoSuchChannel(m.channel)
		return
	}

	if !channel.members.HasMode(client, Theater) {
		client.Reply(RplNotice(s, client, "you are not +T"))
		return
	}

	for member := range channel.members {
		member.Reply(RplPrivMsg(TheaterClient(m.asNick), channel, m.message))
	}
}

type TheaterActionCommand struct {
	BaseCommand
	channel Name
	asNick  Name
	action  CTCPText
}

func (cmd *TheaterActionCommand) String() string {
	return fmt.Sprintf("THEATER_ACTION(channel=%s, asNick=%s, action=%s)", cmd.channel, cmd.asNick, cmd.action)
}

func (m *TheaterActionCommand) HandleServer(s *Server) {
	client := m.Client()

	if !m.channel.IsChannel() {
		client.ErrNoSuchChannel(m.channel)
		return
	}

	channel := s.channels.Get(m.channel)
	if channel == nil {
		client.ErrNoSuchChannel(m.channel)
		return
	}

	if !channel.members.HasMode(client, Theater) {
		client.Reply(RplNotice(s, client, "you are not +T"))
		return
	}

	for member := range channel.members {
		member.Reply(RplCTCPAction(TheaterClient(m.asNick), channel, m.action))
	}
}
