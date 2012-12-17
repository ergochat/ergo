package irc

import (
	"code.google.com/p/go.crypto/bcrypt"
	"log"
	"net"
	"time"
)

type ClientNameMap map[string]*Client
type ChannelNameMap map[string]*Channel
type UserNameMap map[string]*User
type ServiceNameMap map[string]*Service

type Command interface {
	ClientMessage
	Handle(*Server)
}

type Server struct {
	hostname string
	ctime    time.Time
	name     string
	password []byte
	users    UserNameMap
	channels ChannelNameMap
	services ServiceNameMap
	commands chan<- Command
}

func NewServer(name string) *Server {
	commands := make(chan Command)
	server := &Server{
		ctime:    time.Now(),
		name:     name,
		commands: commands,
		users:    make(UserNameMap),
		channels: make(ChannelNameMap),
		services: make(ServiceNameMap),
	}
	go server.receiveCommands(commands)
	NewNickServ(server)
	return server
}

func (server *Server) receiveCommands(commands <-chan Command) {
	for command := range commands {
		log.Printf("%s %T %+v", server.Id(), command, command)
		command.Client().atime = time.Now()
		command.Handle(server)
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
func (s *Server) InterestedUsers(fromUser *User) UserSet {
	users := make(UserSet)
	users.Add(fromUser)
	for channel := range fromUser.channels {
		for user := range channel.members {
			users.Add(user)
		}
	}

	return users
}

// server functionality

func (s *Server) tryRegister(c *Client) {
	if !c.registered && c.HasNick() && c.HasUser() && (s.password == nil || c.serverPass) {
		c.registered = true
		replies := []Reply{RplWelcome(s, c), RplYourHost(s, c), RplCreated(s), RplMyInfo(s)}
		for _, reply := range replies {
			c.replies <- reply
		}
	}
}

func (s *Server) Id() string {
	return s.hostname
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

func (m *UnknownCommand) Handle(s *Server) {
	m.Client().replies <- ErrUnknownCommand(s, m.command)
}

func (m *PingCommand) Handle(s *Server) {
	m.Client().replies <- RplPong(s)
}

func (m *PongCommand) Handle(s *Server) {
	// no-op
}

func (m *PassCommand) Handle(s *Server) {
	err := bcrypt.CompareHashAndPassword(s.password, []byte(m.password))
	if err != nil {
		m.Client().replies <- ErrPasswdMismatch(s)
		return
	}

	m.Client().serverPass = true
	// no reply?
}

func (m *NickCommand) Handle(s *Server) {
	c := m.Client()
	if c.user == nil {
		c.replies <- RplNick(c, m.nickname)
		c.nick = m.nickname
		s.tryRegister(c)
		return
	}

	c.user.replies <- ErrNoPrivileges(s)
}

func (m *UserMsgCommand) Handle(s *Server) {
	c := m.Client()
	if c.username != "" {
		c.replies <- ErrAlreadyRegistered(s)
		return
	}

	c.username, c.realname = m.user, m.realname
	s.tryRegister(c)
}

func (m *QuitCommand) Handle(s *Server) {
	c := m.Client()

	user := c.user
	if user != nil {
		reply := RplQuit(c, m.message)
		for user := range s.InterestedUsers(c.user) {
			user.replies <- reply
		}
	}
	c.conn.Close()
	if user == nil {
		return
	}

	user.LogoutClient(c)
	if !user.HasClients() {
		cmd := &PartCommand{
			BaseCommand: &BaseCommand{c},
		}
		for channel := range user.channels {
			channel.commands <- cmd
		}
	}
}

func (m *JoinCommand) Handle(s *Server) {
	c := m.Client()

	if c.user == nil {
		for name := range m.channels {
			c.replies <- ErrNoSuchChannel(s, name)
		}
		return
	}

	if m.zero {
		cmd := &PartCommand{
			BaseCommand: &BaseCommand{c},
		}
		for channel := range c.user.channels {
			channel.commands <- cmd
		}
		return
	}

	for name := range m.channels {
		s.GetOrMakeChannel(name).commands <- m
	}
}

func (m *PartCommand) Handle(s *Server) {
	user := m.Client().user

	if user == nil {
		for _, chname := range m.channels {
			m.Client().replies <- ErrNoSuchChannel(s, chname)
		}
		return
	}

	for _, chname := range m.channels {
		channel := s.channels[chname]

		if channel == nil {
			user.replies <- ErrNoSuchChannel(s, channel.name)
			continue
		}

		channel.commands <- m
	}
}

func (m *TopicCommand) Handle(s *Server) {
	user := m.Client().user

	if user == nil {
		m.Client().replies <- ErrNoSuchChannel(s, m.channel)
		return
	}

	channel := s.channels[m.channel]
	if channel == nil {
		user.replies <- ErrNoSuchChannel(s, m.channel)
		return
	}

	channel.commands <- m
}

func (m *PrivMsgCommand) Handle(s *Server) {
	service := s.services[m.target]
	if service != nil {
		service.commands <- m
		return
	}

	user := m.Client().user
	if user == nil {
		m.Client().replies <- ErrNoSuchNick(s, m.target)
		return
	}

	if m.TargetIsChannel() {
		channel := s.channels[m.target]
		if channel == nil {
			user.replies <- ErrNoSuchChannel(s, m.target)
			return
		}

		channel.commands <- m
		return
	}

	target := s.users[m.target]
	if target == nil {
		user.replies <- ErrNoSuchNick(s, m.target)
		return
	}

	target.commands <- m
}

func (m *ModeCommand) Handle(s *Server) {
	m.Client().replies <- RplUModeIs(s, m.Client())
}
