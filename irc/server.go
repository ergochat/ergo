package irc

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

type Server struct {
	channels  ChannelNameMap
	commands  chan<- Command
	ctime     time.Time
	hostname  string
	name      string
	operators map[string]string
	password  string
	clients   ClientNameMap
}

func NewServer(config *Config) *Server {
	commands := make(chan Command)
	server := &Server{
		channels:  make(ChannelNameMap),
		clients:   make(ClientNameMap),
		commands:  commands,
		ctime:     time.Now(),
		name:      config.Name,
		operators: make(map[string]string),
		password:  config.Password,
	}

	for _, opConf := range config.Operators {
		server.operators[opConf.Name] = opConf.Password
	}

	go server.receiveCommands(commands)

	for _, listenerConf := range config.Listeners {
		go server.listen(listenerConf)
	}

	return server
}

func (server *Server) receiveCommands(commands <-chan Command) {
	for command := range commands {
		if DEBUG_SERVER {
			log.Printf("%s → %s : %s", command.Client(), server, command)
		}
		client := command.Client()
		client.Touch()

		if !client.serverPass {
			if server.password == "" {
				client.serverPass = true

			} else if _, ok := command.(*PassCommand); !ok {
				client.Reply(ErrPasswdMismatch(server))
				client.Destroy()
				return
			}
		}
		command.HandleServer(server)
	}
}

func newListener(config ListenerConfig) (net.Listener, error) {
	if config.IsTLS() {
		certificate, err := tls.LoadX509KeyPair(config.Certificate, config.Key)
		if err != nil {
			return nil, err
		}
		return tls.Listen("tcp", config.Address, &tls.Config{
			Certificates:             []tls.Certificate{certificate},
			PreferServerCipherSuites: true,
			MinVersion:               tls.VersionTLS12,
		})
	}

	return net.Listen("tcp", config.Address)
}

func (s *Server) listen(config ListenerConfig) {
	listener, err := newListener(config)
	if err != nil {
		log.Fatal("Server.Listen: ", err)
	}

	s.hostname = LookupHostname(listener.Addr())
	log.Print("Server.Listen: listening on ", config.Address)

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
	if !c.registered && c.HasNick() && c.HasUsername() {
		c.registered = true
		replies := []Reply{
			RplWelcome(s, c),
			RplYourHost(s),
			RplCreated(s),
			RplMyInfo(s),
		}
		for _, reply := range replies {
			c.Reply(reply)
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
	m.Client().Reply(ErrUnknownCommand(s, m.command))
}

func (m *PingCommand) HandleServer(s *Server) {
	m.Client().Reply(RplPong(s, m.Client()))
}

func (m *PongCommand) HandleServer(s *Server) {
	// no-op
}

func (m *PassCommand) HandleServer(s *Server) {
	if s.password != m.password {
		m.Client().Reply(ErrPasswdMismatch(s))
		m.Client().Destroy()
		return
	}

	m.Client().serverPass = true
	// no reply?
}

func (m *NickCommand) HandleServer(s *Server) {
	c := m.Client()

	if s.clients[m.nickname] != nil {
		c.Reply(ErrNickNameInUse(s, m.nickname))
		return
	}

	if !c.HasNick() {
		c.nick = m.nickname
	}
	reply := RplNick(c, m.nickname)
	for iclient := range c.InterestedClients() {
		iclient.Reply(reply)
	}

	s.clients.Remove(c)
	c.nick = m.nickname
	s.clients.Add(c)

	s.tryRegister(c)
}

func (m *UserMsgCommand) HandleServer(s *Server) {
	c := m.Client()
	if c.registered {
		c.Reply(ErrAlreadyRegistered(s))
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

	c.Reply(RplError(s, c))
	c.Destroy()

	reply := RplQuit(c, m.message)
	for client := range c.InterestedClients() {
		client.Reply(reply)
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
			m.Client().Reply(ErrNoSuchChannel(s, channel.name))
			continue
		}

		channel.commands <- m
	}
}

func (m *TopicCommand) HandleServer(s *Server) {
	channel := s.channels[m.channel]
	if channel == nil {
		m.Client().Reply(ErrNoSuchChannel(s, m.channel))
		return
	}

	channel.commands <- m
}

func (m *PrivMsgCommand) HandleServer(s *Server) {
	if m.TargetIsChannel() {
		channel := s.channels[m.target]
		if channel == nil {
			m.Client().Reply(ErrNoSuchChannel(s, m.target))
			return
		}

		channel.commands <- m
		return
	}

	target := s.clients[m.target]
	if target == nil {
		m.Client().Reply(ErrNoSuchNick(s, m.target))
		return
	}
	target.Reply(RplPrivMsg(m.Client(), target, m.message))
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
		client.Reply(RplUModeIs(s, client))
		return
	}

	client.Reply(ErrUsersDontMatch(client))
}

func (m *WhoisCommand) HandleServer(server *Server) {
	client := m.Client()

	// TODO implement target query
	if m.target != "" {
		client.Reply(ErrNoSuchServer(server, m.target))
		return
	}

	for _, mask := range m.masks {
		// TODO implement wildcard matching
		mclient := server.clients[mask]
		if mclient != nil {
			client.Reply(RplWhoisUser(server, mclient))
		}
	}
	client.Reply(RplEndOfWhois(server))
}

func (msg *ChannelModeCommand) HandleServer(server *Server) {
	client := msg.Client()
	channel := server.channels[msg.channel]
	if channel == nil {
		client.Reply(ErrNoSuchChannel(server, msg.channel))
		return
	}
	channel.commands <- msg
}

func whoChannel(client *Client, server *Server, channel *Channel) {
	for member := range channel.members {
		client.Reply(RplWhoReply(server, channel, member))
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
			client.Reply(RplWhoReply(server, mclient.channels.First(), mclient))
		}
	}

	client.Reply(RplEndOfWho(server, mask))
}

func (msg *OperCommand) HandleServer(server *Server) {
	client := msg.Client()

	if server.operators[msg.name] != msg.password {
		client.Reply(ErrPasswdMismatch(server))
		return
	}

	client.operator = true

	client.Reply(RplYoureOper(server))
	client.Reply(RplUModeIs(server, client))
}
