package irc

import (
	"code.google.com/p/go.crypto/bcrypt"
	"log"
	"net"
	"time"
)

const (
	DEBUG_SERVER = true
)

type ChannelNameMap map[string]*Channel
type ClientNameMap map[string]*Client

type Server struct {
	channels ChannelNameMap
	commands chan<- Command
	ctime    time.Time
	hostname string
	name     string
	password []byte
	clients  ClientNameMap
}

func NewServer(name string) *Server {
	commands := make(chan Command)
	server := &Server{
		ctime:    time.Now(),
		name:     name,
		commands: commands,
		clients:  make(ClientNameMap),
		channels: make(ChannelNameMap),
	}
	go server.receiveCommands(commands)
	return server
}

func (server *Server) receiveCommands(commands <-chan Command) {
	for command := range commands {
		if DEBUG_SERVER {
			log.Printf("%s → %s : %s", command.Client(), server, command)
		}
		command.Client().atime = time.Now()
		command.HandleServer(server)
	}
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
		NewClient(s, conn)
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

// Send a message to clients of channels fromClient is a member.
func (s *Server) interestedClients(fromClient *Client) ClientSet {
	clients := make(ClientSet)
	clients[fromClient] = true
	for channel := range fromClient.channels {
		for client := range channel.members {
			clients[client] = true
		}
	}

	return clients
}

// server functionality

func (s *Server) tryRegister(c *Client) {
	if !c.registered && c.HasNick() && c.HasUsername() && s.CheckPassword(c) {
		c.registered = true
		replies := []Reply{
			RplWelcome(s, c),
			RplYourHost(s),
			RplCreated(s),
			RplMyInfo(s),
		}
		for _, reply := range replies {
			c.Replies() <- reply
		}
	}
}

func (s *Server) CheckPassword(c *Client) bool {
	return (s.password == nil) || c.serverPass
}

func (s *Server) Id() string {
	return s.name
}

func (s *Server) String() string {
	return s.Id()
}

func (s *Server) PublicId() string {
	return s.Id()
}

func (s *Server) Nick() string {
	return s.name
}

func (s *Server) DeleteChannel(channel *Channel) {
	delete(s.channels, channel.name)
}

//
// commands
//

func (m *UnknownCommand) HandleServer(s *Server) {
	m.Client().Replies() <- ErrUnknownCommand(s, m.command)
}

func (m *PingCommand) HandleServer(s *Server) {
	m.Client().Replies() <- RplPong(s)
}

func (m *PongCommand) HandleServer(s *Server) {
	// no-op
}

func (m *PassCommand) HandleServer(s *Server) {
	err := bcrypt.CompareHashAndPassword(s.password, []byte(m.password))
	if err != nil {
		m.Client().Replies() <- ErrPasswdMismatch(s)
		return
	}

	m.Client().serverPass = true
	// no reply?
}

func (m *NickCommand) HandleServer(s *Server) {
	c := m.Client()

	if s.clients[m.nickname] != nil {
		c.replies <- ErrNickNameInUse(s, m.nickname)
		return
	}

	reply := RplNick(c, m.nickname)
	for iclient := range s.interestedClients(c) {
		iclient.replies <- reply
	}

	if c.HasNick() {
		delete(s.clients, c.nick)
	}
	s.clients[m.nickname] = c
	c.nick = m.nickname

	s.tryRegister(c)
}

func (m *UserMsgCommand) HandleServer(s *Server) {
	c := m.Client()
	if c.registered {
		c.replies <- ErrAlreadyRegistered(s)
		return
	}

	c.username, c.realname = m.user, m.realname
	s.tryRegister(c)
}

func (m *QuitCommand) HandleServer(s *Server) {
	c := m.Client()

	reply := RplQuit(c, m.message)
	for client := range s.interestedClients(c) {
		client.replies <- reply
	}
	c.conn.Close()
	cmd := &PartCommand{
		BaseCommand: BaseCommand{c},
	}
	for channel := range c.channels {
		channel.commands <- cmd
	}
}

func (m *JoinCommand) HandleServer(s *Server) {
	c := m.Client()

	if m.zero {
		cmd := &PartCommand{
			BaseCommand: BaseCommand{c},
		}
		for channel := range c.channels {
			channel.commands <- cmd
		}
		return
	}

	for name := range m.channels {
		s.GetOrMakeChannel(name).commands <- m
	}
}

func (m *PartCommand) HandleServer(s *Server) {
	for _, chname := range m.channels {
		channel := s.channels[chname]

		if channel == nil {
			m.Client().replies <- ErrNoSuchChannel(s, channel.name)
			continue
		}

		channel.commands <- m
	}
}

func (m *TopicCommand) HandleServer(s *Server) {
	channel := s.channels[m.channel]
	if channel == nil {
		m.Client().replies <- ErrNoSuchChannel(s, m.channel)
		return
	}

	channel.commands <- m
}

func (m *PrivMsgCommand) HandleServer(s *Server) {
	if m.TargetIsChannel() {
		channel := s.channels[m.target]
		if channel == nil {
			m.Client().replies <- ErrNoSuchChannel(s, m.target)
			return
		}

		channel.commands <- m
		return
	}

	target := s.clients[m.target]
	if target == nil {
		m.Client().replies <- ErrNoSuchNick(s, m.target)
		return
	}

	target.commands <- m
}

func (m *ModeCommand) HandleServer(s *Server) {
	m.Client().replies <- RplUModeIs(s, m.Client())
}
