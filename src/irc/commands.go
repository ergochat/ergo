package irc

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Message interface {
	Handle(s *Server, c *Client)
}

var (
	NotEnoughArgsError    = errors.New("not enough arguments")
	UModeUnknownFlagError = errors.New("unknown umode flag")
)

// unknown

type UnknownMessage struct {
	command string
}

// NB: no constructor, created on demand in parser for invalid messages.

func (m *UnknownMessage) Handle(s *Server, c *Client) {
	c.send <- ErrUnknownCommand(s, m.command)
}

// PING

type PingMessage struct {
	server  string
	server2 string
}

func NewPingMessage(args []string) (Message, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	msg := &PingMessage{server: args[0]}
	if len(args) > 1 {
		msg.server2 = args[1]
	}
	return msg, nil
}

func (m *PingMessage) Handle(s *Server, c *Client) {
	c.send <- RplPong(s)
}

// PONG

type PongMessage struct {
	server1 string
	server2 string
}

func NewPongMessage(args []string) (Message, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	message := &PongMessage{server1: args[0]}
	if len(args) > 1 {
		message.server2 = args[1]
	}
	return message, nil
}

func (m *PongMessage) Handle(s *Server, c *Client) {
	// no-op
}

// PASS <password>

type PassMessage struct {
	password string
}

func NewPassMessage(args []string) (Message, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	return &PassMessage{password: args[0]}
}

func (m *PassMessage) Handle(s *Server, c *Client) {
	if m.password == server.password {
		c.serverPass = true
	} else {
		c.send <- ErrPass
	}
}

// NICK

type NickMessage struct {
	nickname string
}

func NewNickMessage(args []string) (Message, error) {
	if len(args) != 1 {
		return nil, NotEnoughArgsError
	}
	return &NickMessage{args[0]}, nil
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

func NewUserMessage(args []string) (Message, error) {
	if len(args) != 4 {
		return nil, NotEnoughArgsError
	}
	msg := &UserMessage{
		user:     args[0],
		unused:   args[2],
		realname: args[3],
	}
	mode, err := strconv.ParseUint(args[1], 10, 8)
	if err == nil {
		msg.mode = uint8(mode)
	}
	return msg, nil
}

func (m *UserMessage) Handle(s *Server, c *Client) {
	s.UserLogin(c, m.user, m.realname)
}

// QUIT [ <Quit Message> ]

type QuitMessage struct {
	message string
}

func NewQuitMessage(args []string) (Message, error) {
	msg := &QuitMessage{}
	if len(args) > 0 {
		msg.message = args[0]
	}
	return msg, nil
}

func (m *QuitMessage) Handle(s *Server, c *Client) {
	s.Quit(c, m.message)
}

// MODE <nickname> *( ( "+" / "-" ) *( "i" / "w" / "o" / "O" / "r" ) )

type ModeMessage struct {
	nickname string
	modes    []string
}

// mode s is accepted but ignored, like some other modes
var MODE_RE = regexp.MustCompile("^[-+][iwroOs]+$")

func NewModeMessage(args []string) (Message, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	msg := &ModeMessage{
		nickname: args[0],
	}
	for _, arg := range args[1:] {
		if !MODE_RE.MatchString(arg) {
			return nil, ErrUModeUnknownFlag
		}
		prefix := arg[0]
		for _, c := range arg[1:] {
			mode := fmt.Sprintf("%c%c", prefix, c)
			msg.modes = append(msg.modes, mode)
		}
	}
	return msg, nil
}

func (m *ModeMessage) Handle(s *Server, c *Client) {
	if m.nickname != c.nick {
		c.send <- ErrUsersDontMatch(s)
		return
	}
	s.ChangeUserMode(c, m.modes)
}

// JOIN ( <channel> *( "," <channel> ) [ <key> *( "," <key> ) ] ) / "0"

type JoinMessage struct {
	channels []string
	keys     []string
	zero     bool
}

func NewJoinMessage(args []string) (Message, error) {
	msg := &JoinMessage{}
	if len(args) > 0 {
		if args[0] == "0" {
			msg.zero = true
		} else {
			msg.channels = strings.Split(args[0], ",")
		}

		if len(args) > 1 {
			msg.keys = strings.Split(args[1], ",")
		}
	}
	return msg, nil
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

func NewPartMessage(args []string) (Message, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	msg := &PartMessage{channels: strings.Split(args[0], ",")}
	if len(args) > 1 {
		msg.message = args[1]
	}
	return msg, nil
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

func NewPrivMsgMessage(args []string) (Message, error) {
	if len(args) < 2 {
		return nil, NotEnoughArgsError
	}
	return &PrivMsgMessage{
		target:  args[0],
		message: args[1],
	}, nil
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

// TOPIC [newtopic]

type TopicMessage struct {
	channel string
	topic   string
}

func NewTopicMessage(args []string) (Message, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	msg := &TopicMessage{channel: args[0]}
	if len(args) > 1 {
		msg.topic = args[1]
	}
	return msg, nil
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

// INVITE <nickname> <channel>

type InviteMessage struct {
	nickname string
	channel  string
}

func NewInviteMessage(args []string) (Message, error) {
	if len(args) < 2 {
		return nil, NotEnoughArgsError
	}
	return &InviteMessage{
		nickname: args[0],
		channel:  args[1],
	}, nil
}

func (m *InviteMessage) Handle(s *Server, c *Client) {
	channel := s.channels[m.channel]
	if channel == nil {
		c.send <- ErrNoSuchNick(s, m.channel)
		return
	}

	invitee := s.nicks[m.nickname]
	if invitee == nil {
		c.send <- ErrNoSuchNick(s, m.nickname)
		return
	}

	channel.Invite(c, invitee)
}

// OPER <name> <password>

type OperMessage struct {
	name     string
	password string
}

func NewOperMessage(args []string) Message {
	if len(args) < 2 {
		return nil, NotEnoughArgsError
	}
	return &OperMessage{
		name:     args[0],
		password: args[1],
	}
}

func (m *OperMessage) Handle(s *Server, c *Client) {
	if s.operators[m.name] == m.password {
		c.send <- RplYoureOper(s)
	} else {
		c.send <- ErrPasswdMismatch(s)
	}
}
