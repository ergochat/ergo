package irc

import (
	"log"
	"net"
	"regexp"
	"strings"
)

type Server struct {
	ch chan Message
	nicks map[string]*Client
}

func NewServer() *Server {
	server := Server{make(chan Message), make(map[string]*Client)}
	go server.Receive()
	return &server
}

func (s *Server) Listen(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("Server.Listen: ", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print("Server.Listen: ", err)
			continue
		}
		go NewClient(conn).Communicate(s)
	}
}

func (s *Server) Receive() {
	for message := range s.ch {
		log.Printf("C -> S: %s %s", message.command, message.args)
		switch message.command {
		case "PING":
			message.client.Send(MessagePong())
		case "USER":
			s.UserCommand(message.client, message.args)
		case "NICK":
			s.NickCommand(message.client, message.args)
		case "QUIT":
			s.QuitCommand(message.client, message.args)
		default:
			message.client.Send(ErrUnknownCommand(message.client.Nick(), message.command))
		}
	}
}

func (s *Server) Send(m Message) {
	s.ch <- m
}

// commands

func (s *Server) UserCommand(c *Client, args string) {
	parts := strings.SplitN(args, " ", 4)
	username, _, _, realname := parts[0], parts[1], parts[2], parts[3]
	if c.username != "" {
		c.Send(ErrAlreadyRegistered(c.nick))
		return
	}
	c.username, c.realname = username, realname
	s.TryRegister(c)
}

func (s *Server) NickCommand(c *Client, nick string) {
	if s.nicks[nick] != nil {
		c.Send(ErrNickNameInUse(nick))
		return
	}
	c.nick = nick
	s.nicks[nick] = c
	s.TryRegister(c)
}

func (s *Server) TryRegister(c *Client) {
	if (!c.registered && c.nick != "" && c.username != "") {
		c.registered = true
		c.Send(
			ReplyWelcome(c.Nick(), c.username, "localhost"),
			ReplyYourHost(c.Nick(), "irc.jlatt.com"),
			ReplyCreated(c.Nick(), "2012/04/07"),
			ReplyMyInfo(c.Nick(), "irc.jlatt.com"))
	}
}

func (s *Server) QuitCommand(c *Client, args string) {
	re := regexp.MustCompile("^" + RE_QUIT + "$")
	matches := re.FindAllStringSubmatch(args, -1)
	if matches != nil {
		c.Send(MessageError())
	}
	delete(s.nicks, c.nick)
}
