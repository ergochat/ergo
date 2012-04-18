package irc

import (
	"strconv"
	"strings"
)

type Message interface {
	Handle(s *Server, c *Client)
}

type NewMessageFunc func([]string) Message

type NickMessage struct {
	nickname string
}

func NewNickMessage(args []string) Message {
	if len(args) != 1 {
		return nil
	}
	return &NickMessage{args[0]}
}

func (m *NickMessage) Handle(s *Server, c *Client) {
	if s.nicks[m.nickname] != nil {
		c.send <- ErrNickNameInUse(m.nickname)
		return
	}
	if c.nick != "" {
		delete(s.nicks, c.nick)
	}
	c.nick = m.nickname
	s.nicks[c.nick] = c
	tryRegister(s, c)
}

type UserMessage struct {
	user string
	mode uint8
	unused string
	realname string
}

func NewUserMessage(args []string) Message {
	if len(args) != 4 {
		return nil
	}
	msg := new(UserMessage)
	msg.user = args[0]
	mode, err := strconv.ParseUint(args[1], 10, 8)
	if err == nil {
		msg.mode = uint8(mode)
	}
	msg.unused = args[2]
	msg.realname = args[3]
	return msg
}

func (m *UserMessage) Handle(s *Server, c *Client) {
	if c.username != "" {
		c.send <- ErrAlreadyRegistered(c.Nick())
		return
	}
	c.username, c.realname = m.user, m.realname
	tryRegister(s, c)
}

type QuitMessage struct {
	message string
}

func NewQuitMessage(args []string) Message {
	msg := QuitMessage{}
	if len(args) > 0 {
		msg.message = args[0]
	}
	return &msg
}

func (m *QuitMessage) Handle(s *Server, c *Client) {
	c.send <- MessageError()
	delete(s.nicks, c.nick)
}

type UnknownMessage struct {
	command string
}

func (m *UnknownMessage) Handle(s *Server, c *Client) {
	c.send <- ErrUnknownCommand(c.Nick(), m.command)
}

type PingMessage struct {}

func NewPingMessage(args []string) Message {
	return &PingMessage{}
}

func (m *PingMessage) Handle(s *Server, c *Client) {
	c.send <- MessagePong()
}

func tryRegister(s *Server, c *Client) {
	if (!c.registered && c.nick != "" && c.username != "") {
		c.registered = true
		c.send <- ReplyWelcome(c.Nick(), c.username, "localhost")
		c.send <- ReplyYourHost(c.Nick(), "irc.jlatt.com")
		c.send <- ReplyCreated(c.Nick(), "2012/04/07")
		c.send <- ReplyMyInfo(c.Nick(), "irc.jlatt.com")
	}
}

func parseArg(line string) (string, string) {
	if line == "" {
		return "", ""
	}

	if strings.HasPrefix(line, ":") {
		return line[1:], ""
	}

	parts := strings.SplitN(line, " ", 2)
	arg := parts[0]
	rest := ""
	if len(parts) > 1 {
		rest = parts[1]
	}
	return arg, rest
}

func parseLine(line string) (string, []string) {
	args := make([]string, 0)
	for arg, rest := parseArg(line); arg != ""; arg, rest = parseArg(rest) {
		args = append(args, arg)
	}
	return args[0], args[1:]
}

var commands = map[string]NewMessageFunc {
	"NICK": NewNickMessage,
	"PING": NewPingMessage,
	"QUIT": NewQuitMessage,
	"USER": NewUserMessage,
}

func ParseMessage(line string) Message {
	command, args := parseLine(line)
	constructor := commands[command]
	var msg Message
	if constructor != nil {
		msg = constructor(args)
	}
	if msg == nil {
		msg = &UnknownMessage{command}
	}
	return msg
}
