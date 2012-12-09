package irc

type Message interface {
	Handle(s *Server, c *Client)
}

// unknown

type UnknownMessage struct {
	command string
}

func (m *UnknownMessage) Handle(s *Server, c *Client) {
	c.send <- ErrUnknownCommand(s, m.command)
}

// PING

type PingMessage struct {
	server  string
	server2 string
}

func (m *PingMessage) Handle(s *Server, c *Client) {
	c.send <- RplPong(s)
}

// PONG

type PongMessage struct {
	server1 string
	server2 string
}

func (m *PongMessage) Handle(s *Server, c *Client) {
	// TODO update client atime
}

// NICK

type NickMessage struct {
	nickname string
}

func (m *NickMessage) Handle(s *Server, c *Client) {
	s.ChangeNick(c, m.nickname)
}

// USER

type UserMessage struct {
	user     string
	mode     uint8
	unused   string
	realname string
}

func (m *UserMessage) Handle(s *Server, c *Client) {
	s.Register(c, m.user, m.realname)
}

// QUIT

type QuitMessage struct {
	message string
}

func (m *QuitMessage) Handle(s *Server, c *Client) {
	s.Quit(c, m.message)
}

// MODE

type ModeMessage struct {
	nickname string
	modes    []string
}

func (m *ModeMessage) Handle(s *Server, c *Client) {
	if m.nickname != c.nick {
		c.send <- ErrUsersDontMatch(s)
		return
	}
	s.ChangeUserMode(c, m.modes)
}

// JOIN

type JoinMessage struct {
	channels []string
	keys     []string
	zero     bool
}

func (m *JoinMessage) Handle(s *Server, c *Client) {
	if m.zero {
		for channel := range c.channels {
			channel.Part(c, "")
		}
	} else {
		for i, name := range m.channels {
			key := ""
			if len(m.keys) > i {
				key = m.keys[i]
			}

			s.GetOrMakeChannel(name).Join(c, key)
		}
	}
}

// PART

type PartMessage struct {
	channels []string
	message  string
}

func (m *PartMessage) Handle(s *Server, c *Client) {
	for _, chname := range m.channels {
		channel := s.channels[chname]

		if channel == nil {
			c.send <- ErrNoSuchChannel(s, chname)
			continue
		}

		channel.Part(c, m.message)
	}
}

// PRIVMSG

type PrivMsgMessage struct {
	target  string
	message string
}

func (m *PrivMsgMessage) TargetIsChannel() bool {
	switch m.target[0] {
	case '&', '#', '+', '!':
		return true
	}
	return false
}

func (m *PrivMsgMessage) Handle(s *Server, c *Client) {
	if m.TargetIsChannel() {
		channel := s.channels[m.target]
		if channel != nil {
			channel.PrivMsg(c, m.message)
		} else {
			c.send <- ErrNoSuchNick(s, m.target)
		}
	} else {
		client := s.nicks[m.target]
		if client != nil {
			client.send <- RplPrivMsg(client, m.message)
		} else {
			c.send <- ErrNoSuchNick(s, m.target)
		}
	}
}

// TOPIC

type TopicMessage struct {
	channel string
	topic   string
}

func (m *TopicMessage) Handle(s *Server, c *Client) {
	channel := s.channels[m.channel]
	if channel == nil {
		c.send <- ErrNoSuchChannel(s, m.channel)
		return
	}
	if m.topic == "" {
		channel.GetTopic(c)
	} else {
		channel.ChangeTopic(c, m.topic)
	}
}
