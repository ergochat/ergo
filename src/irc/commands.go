package irc

type Message interface {
	Handle(s *Server, c *Client)
}

func (m *NickMessage) Handle(s *Server, c *Client) {
	if s.nicks[m.nickname] != nil {
		c.send <- ErrNickNameInUse(m.nickname)
		return
	}
	oldNick := c.nick
	if c.nick != "" {
		delete(s.nicks, c.nick)
	}
	c.nick = m.nickname
	s.nicks[c.nick] = c
	if c.registered {
		c.send <- ReplyNick(oldNick, c)
	} else {
		tryRegister(s, c)
	}
}

func (m *UserMessage) Handle(s *Server, c *Client) {
	if c.username != "" {
		c.send <- ErrAlreadyRegistered(c.Nick())
		return
	}
	c.username, c.realname = m.user, m.realname
	tryRegister(s, c)
}

func (m *QuitMessage) Handle(s *Server, c *Client) {
	c.send <- MessageError()
	c.conn.Close()
	delete(s.nicks, c.nick)
}

func (m *UnknownMessage) Handle(s *Server, c *Client) {
	c.send <- ErrUnknownCommand(c.Nick(), m.command)
}

func (m *PingMessage) Handle(s *Server, c *Client) {
	c.send <- MessagePong()
}

func (m *ModeMessage) Handle(s *Server, c *Client) {
	if m.nickname != c.nick {
		c.send <- ErrUsersDontMatch(c.Nick())
		return
	}
	for _, mode := range m.modes {
		if mode == "+i" {
			c.invisible = true
		} else if mode == "-i" {
			c.invisible = false
		}
	}
	c.send <- ReplyUModeIs(c)
}

func tryRegister(s *Server, c *Client) {
	if (!c.registered && c.HasNick() && c.HasUser()) {
		c.registered = true
		c.send <- ReplyWelcome(c)
		c.send <- ReplyYourHost(c.Nick(), s.name)
		c.send <- ReplyCreated(c.Nick(), "2012/04/07")
		c.send <- ReplyMyInfo(c.Nick(), s.name)
	}
}
