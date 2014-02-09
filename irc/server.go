package irc

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

type Server struct {
	channels ChannelNameMap
	commands chan<- Command
	ctime    time.Time
	hostname string
	name     string
	password string
	clients  ClientNameMap
}

func NewServer(config *Config) *Server {
	commands := make(chan Command)
	server := &Server{
		ctime:    time.Now(),
		name:     config.Name,
		commands: commands,
		clients:  make(ClientNameMap),
		channels: make(ChannelNameMap),
	}
	go server.receiveCommands(commands)
	go server.listen(config.Listen)
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

func (s *Server) listen(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("Server.Listen: ", err)
	}

	s.hostname = LookupHostname(listener.Addr())
	log.Print("Server.Listen: listening on ", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print("Server.Accept: ", err)
			continue
		}
		if DEBUG_SERVER {
			log.Print("Server.Accept: ", conn.RemoteAddr())
		}
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

func (s *Server) GenerateGuestNick() string {
	bytes := make([]byte, 8)
	for {
		_, err := rand.Read(bytes)
		if err != nil {
			panic(err)
		}
		randInt, n := binary.Uvarint(bytes)
		if n <= 0 {
			continue // TODO handle error
		}
		nick := fmt.Sprintf("guest%d", randInt)
		if s.clients[nick] == nil {
			return nick
		}
	}
}

// server functionality

func (s *Server) tryRegister(c *Client) {
	if !c.registered && c.HasNick() && c.HasUsername() && c.serverPass {
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

func (s *Server) Id() string {
	return s.name
}

func (s *Server) String() string {
	return s.name
}

func (s *Server) Nick() string {
	return s.Id()
}

//
// commands
//

func (m *UnknownCommand) HandleServer(s *Server) {
	m.Client().replies <- ErrUnknownCommand(s, m.command)
}

func (m *PingCommand) HandleServer(s *Server) {
	m.Client().replies <- RplPong(s, m.Client())
}

func (m *PongCommand) HandleServer(s *Server) {
	// no-op
}

func (m *PassCommand) HandleServer(s *Server) {
	if s.password != m.password {
		m.Client().replies <- ErrPasswdMismatch(s)
		m.Client().Destroy()
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
	c.replies <- reply
	for iclient := range c.InterestedClients() {
		iclient.replies <- reply
	}

	s.clients.Remove(c)
	c.nick = m.nickname
	s.clients.Add(c)

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

	s.clients.Remove(c)
	for channel := range c.channels {
		channel.members.Remove(c)
	}

	c.replies <- RplError(s, c)
	c.Destroy()

	reply := RplQuit(c, m.message)
	for client := range c.InterestedClients() {
		client.replies <- reply
	}
}

func (m *JoinCommand) HandleServer(s *Server) {
	c := m.Client()

	if m.zero {
		cmd := &PartCommand{}
		cmd.SetClient(c)
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
	target.replies <- RplPrivMsg(m.Client(), target, m.message)
}

func (m *ModeCommand) HandleServer(s *Server) {
	client := m.Client()
	if client.Nick() == m.nickname {
		for _, change := range m.changes {
			if change.mode == Invisible {
				switch change.op {
				case Add:
					client.invisible = true
				case Remove:
					client.invisible = false
				}
			}
		}
		client.replies <- RplUModeIs(s, client)
		return
	}

	client.replies <- ErrUsersDontMatch(client)
}

func (m *WhoisCommand) HandleServer(server *Server) {
	client := m.Client()

	// TODO implement target query
	if m.target != "" {
		client.replies <- ErrNoSuchServer(server, m.target)
		return
	}

	for _, mask := range m.masks {
		// TODO implement wildcard matching
		mclient := server.clients[mask]
		if mclient != nil {
			client.replies <- RplWhoisUser(server, mclient)
		}
	}
	client.replies <- RplEndOfWhois(server)
}

func (msg *ChannelModeCommand) HandleServer(server *Server) {
	client := msg.Client()
	channel := server.channels[msg.channel]
	if channel == nil {
		client.replies <- ErrNoSuchChannel(server, msg.channel)
		return
	}
	channel.commands <- msg
}

func whoChannel(client *Client, server *Server, channel *Channel) {
	for member := range channel.members {
		client.replies <- RplWhoReply(server, channel, member)
	}
}

func (msg *WhoCommand) HandleServer(server *Server) {
	client := msg.Client()
	// TODO implement wildcard matching

	mask := string(msg.mask)
	if mask == "" {
		for _, channel := range server.channels {
			whoChannel(client, server, channel)
		}
	} else if IsChannel(mask) {
		channel := server.channels[mask]
		if channel != nil {
			whoChannel(client, server, channel)
		}
	} else {
		mclient := server.clients[mask]
		if mclient != nil {
			client.replies <- RplWhoReply(server, mclient.channels.First(), mclient)
		}
	}

	client.replies <- RplEndOfWho(server, mask)
}
