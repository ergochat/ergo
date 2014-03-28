package irc

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

	reply := RplPrivMsg(TheaterClient(m.asNick), channel, m.message)
	for member := range channel.members {
		member.Reply(reply)
	}
}

type TheaterActionCommand struct {
	BaseCommand
	channel Name
	asNick  Name
	action  CTCPText
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

	reply := RplCTCPAction(TheaterClient(m.asNick), channel, m.action)
	for member := range channel.members {
		member.Reply(reply)
	}
}
