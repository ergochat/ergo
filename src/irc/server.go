package irc

import (
	"log"
	"net"
	"time"
)

type Server struct {
	hostname  string
	ctime     time.Time
	name      string
	recv      chan<- *ClientMessage
	nicks     map[string]*Client
	channels  map[string]*Channel
	password  string
	operators map[string]string
}

type ClientMessage struct {
	client  *Client
	message Message
}

func NewServer(name string) *Server {
	recv := make(chan *ClientMessage)
	server := &Server{
		ctime:    time.Now(),
		name:     name,
		recv:     recv,
		nicks:    make(map[string]*Client),
		channels: make(map[string]*Channel),
	}
	go func() {
		for m := range recv {
			log.Printf("%s -> %T%+v", m.client.Id(), m.message, m.message)
			m.message.Handle(server, m.client)
		}
	}()
	return server
}

func (s *Server) Listen(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("Server.Listen: ", err)
	}

	s.hostname = LookupHostname(listener.Addr())
	log.Print("Server.Listen: listening on ", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print("Server.Listen: ", err)
			continue
		}
		log.Print("Server.Listen: accepted ", conn.RemoteAddr())
		go NewClient(s, conn).Communicate()
	}
}

func (s *Server) GetOrMakeChannel(name string) *Channel {
	channel := s.channels[name]

	if channel == nil {
		channel = NewChannel(s, name)
		s.channels[name] = channel
	}

	return channel
}

func (s *Server) AddOperator(name string, password string) {
	s.operators[name] = password
}

// Send a message to clients of channels fromClient is a member.
func (s *Server) SendToInterestedClients(fromClient *Client, reply Reply) {
	clients := make(map[*Client]bool)
	clients[fromClient] = true
	for channel := range fromClient.channels {
		for client := range channel.members {
			clients[client] = true
		}
	}

	for client := range clients {
		client.send <- reply
	}
}

// server functionality

func (s *Server) ChangeNick(c *Client, newNick string) {
	if s.nicks[newNick] != nil {
		c.send <- ErrNickNameInUse(s, newNick)
		return
	}

	if c.nick != "" {
		delete(s.nicks, c.nick)
	}
	s.nicks[c.nick] = c

	s.SendToInterestedClients(c, RplNick(c, newNick))

	c.nick = newNick

	s.tryRegister(c)
}

func (s *Server) UserLogin(c *Client, user string, realName string) {
	if c.username != "" {
		c.send <- ErrAlreadyRegistered(s)
		return
	}

	c.username, c.realname = user, realName
	s.tryRegister(c)
}

func (s *Server) tryRegister(c *Client) {
	if !c.registered && c.HasNick() && c.HasUser() && (s.password == "" || c.serverPass) {
		c.registered = true
		c.send <- RplWelcome(s, c)
		c.send <- RplYourHost(s, c)
		c.send <- RplCreated(s)
		c.send <- RplMyInfo(s)
	}
}

func (s *Server) Quit(c *Client, message string) {
	for channel := range c.channels {
		channel.Part(c, message)
	}
	delete(s.nicks, c.nick)

	c.conn.Close()
}

func (s *Server) ChangeUserMode(c *Client, modes []string) {
	for _, mode := range modes {
		switch mode {
		case "+w":
			c.wallOps = true
		case "-w":
			c.wallOps = false
		}
	}
	c.send <- RplUModeIs(s, c)
}

func (s *Server) Id() string {
	return s.hostname
}
