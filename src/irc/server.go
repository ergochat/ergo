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

type Server struct {
	hostname string
	ctime    time.Time
	name     string
	commands chan<- Command
	password []byte
	users    UserNameMap
	channels ChannelNameMap
}

func NewServer(name string) *Server {
	commands := make(chan Command)
	server := &Server{
		ctime:    time.Now(),
		name:     name,
		commands: commands,
		users:    make(UserNameMap),
		channels: make(ChannelNameMap),
	}
	go server.receiveCommands(commands)
	return server
}

func (server *Server) receiveCommands(commands <-chan Command) {
	for command := range commands {
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
	users[fromUser] = true
	for channel := range fromUser.channels {
		for user := range channel.members {
			users[user] = true
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

func (s *Server) ChangeUserMode(c *Client, modes []string) {
	// Don't allow any mode changes.
	c.replies <- RplUModeIs(s, c)
}

func (s *Server) Id() string {
	return s.hostname
}

func (s *Server) PublicId() string {
	return s.Id()
}

func (s *Server) DeleteChannel(channel *Channel) {
	delete(s.channels, channel.name)
}

//
// commands
//

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

func (m *UserCommand) Handle(s *Server) {
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
	reply := RplQuit(c, m.message)
	for user := range s.InterestedUsers(c.user) {
		user.replies <- reply
	}
	c.conn.Close()
	user := c.user
	user.LogoutClient(c)

	if !user.HasClients() {
		cmd := &PartChannelCommand{
			Command: m,
		}
		for channel := range c.user.channels {
			channel.commands <- cmd
		}
	}
}

func (m *JoinCommand) Handle(s *Server) {
	c := m.Client()
	if m.zero {
		cmd := &PartChannelCommand{
			Command: m,
		}
		for channel := range c.user.channels {
			channel.commands <- cmd
		}
	} else {
		for i, name := range m.channels {
			key := ""
			if len(m.keys) > i {
				key = m.keys[i]
			}

			s.GetOrMakeChannel(name).commands <- &JoinChannelCommand{m, key}
		}
	}
}

func (m *PartCommand) Handle(s *Server) {
	user := m.Client().user
	for _, chname := range m.channels {
		channel := s.channels[chname]

		if channel == nil {
			user.replies <- ErrNoSuchChannel(s, channel.name)
			continue
		}

		channel.commands <- &PartChannelCommand{m, m.message}
	}
}

func (m *TopicCommand) Handle(s *Server) {
	user := m.Client().user
	channel := s.channels[m.channel]
	if channel == nil {
		user.replies <- ErrNoSuchChannel(s, m.channel)
		return
	}

	if m.topic == "" {
		channel.commands <- &GetTopicChannelCommand{m}
		return
	}

	channel.commands <- &SetTopicChannelCommand{m}
}

func (m *PrivMsgCommand) Handle(s *Server) {
	user := m.Client().user

	if m.TargetIsChannel() {
		channel := s.channels[m.target]
		if channel == nil {
			user.replies <- ErrNoSuchNick(s, m.target)
			return
		}

		channel.commands <- &PrivMsgChannelCommand{m}
		return
	}

	target := s.users[m.target]
	if target != nil {
		target.replies <- ErrNoSuchNick(s, m.target)
		return
	}

	target.replies <- RplPrivMsg(user, target, m.message)
}

func (m *LoginCommand) Handle(s *Server) {
	client := m.Client()
	if client.user != nil {
		client.replies <- ErrAlreadyRegistered(s)
		return
	}

	user := s.users[m.nick]
	if user == nil {
		client.replies <- ErrNoSuchNick(s, m.nick)
		return
	}

	if !user.Login(client, m.nick, m.password) {
		client.replies <- ErrRestricted(s)
		return
	}

	client.replies <- RplNick(client, m.nick)
	// TODO join channels
}

func (m *ReserveCommand) Handle(s *Server) {
	client := m.Client()
	if client.user != nil {
		client.replies <- ErrAlreadyRegistered(s)
		return
	}

	if s.users[m.nick] != nil {
		client.replies <- ErrNickNameInUse(s, m.nick)
		return
	}

	s.users[m.nick] = NewUser(m.nick, m.password, s)
}
