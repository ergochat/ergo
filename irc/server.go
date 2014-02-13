package irc

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

type Server struct {
	channels  ChannelNameMap
	commands  chan<- Command
	ctime     time.Time
	motdFile  string
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
		motdFile:  config.MOTD,
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
			log.Printf("%s → %s %s", command.Client(), server, command)
		}
		client := command.Client()
		client.Touch()

		if !client.serverPass {
			if server.password == "" {
				client.serverPass = true

			} else {
				switch command.(type) {
				case *PassCommand, *CapCommand, *ProxyCommand:
					// no-op
				default:
					client.Reply(ErrPasswdMismatch(server))
					client.Destroy()
					return
				}
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
		})
	}

	return net.Listen("tcp", config.Address)
}

func (s *Server) listen(config ListenerConfig) {
	listener, err := newListener(config)
	if err != nil {
		log.Fatal("Server.Listen: ", err)
	}

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
		go NewClient(s, conn)
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
		c.Reply(
			RplWelcome(s, c),
			RplYourHost(s),
			RplCreated(s),
			RplMyInfo(s))
		s.MOTD(c)
	}
}

func (server *Server) MOTD(client *Client) {
	if server.motdFile == "" {
		client.Reply(ErrNoMOTD(server))
		return
	}

	file, err := os.Open(server.motdFile)
	if err != nil {
		client.Reply(ErrNoMOTD(server))
		return
	}
	defer file.Close()

	client.Reply(RplMOTDStart(server))
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		if len(line) > 80 {
			for len(line) > 80 {
				client.Reply(RplMOTD(server, line[0:80]))
				line = line[80:]
			}
			if len(line) > 0 {
				client.Reply(RplMOTD(server, line))
			}
		} else {
			client.Reply(RplMOTD(server, line))
		}
	}
	client.Reply(RplMOTDEnd(server))
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

	if m.nickname == "" {
		c.Reply(ErrNoNicknameGiven(s))
		return
	}

	if s.clients[m.nickname] != nil {
		c.Reply(ErrNickNameInUse(s, m.nickname))
		return
	}

	// Make reply before changing nick.
	reply := RplNick(c, m.nickname)

	s.clients.Remove(c)
	c.nick = m.nickname
	s.clients.Add(c)

	iclients := c.InterestedClients()
	iclients.Add(c)
	for iclient := range iclients {
		iclient.Reply(reply)
	}

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

func (m *QuitCommand) HandleServer(server *Server) {
	client := m.Client()
	iclients := client.InterestedClients()
	iclients.Remove(client)

	server.clients.Remove(client)
	for channel := range client.channels {
		channel.members.Remove(client)
	}

	client.Reply(RplError(server, client))
	client.Destroy()

	reply := RplQuit(client, m.message)
	for iclient := range iclients {
		iclient.Reply(reply)
	}
}

func (m *JoinCommand) HandleServer(s *Server) {
	c := m.Client()

	if m.zero {
		cmd := &PartCommand{}
		cmd.SetClient(c)
		for channel := range c.channels {
			channel.Command(cmd)
		}
		return
	}

	for name := range m.channels {
		s.GetOrMakeChannel(name).Command(m)
	}
}

func (m *PartCommand) HandleServer(s *Server) {
	for _, chname := range m.channels {
		channel := s.channels[chname]

		if channel == nil {
			m.Client().Reply(ErrNoSuchChannel(s, channel.name))
			continue
		}

		channel.Command(m)
	}
}

func (m *TopicCommand) HandleServer(s *Server) {
	channel := s.channels[m.channel]
	if channel == nil {
		m.Client().Reply(ErrNoSuchChannel(s, m.channel))
		return
	}

	channel.Command(m)
}

func (m *PrivMsgCommand) HandleServer(s *Server) {
	if m.TargetIsChannel() {
		channel := s.channels[m.target]
		if channel == nil {
			m.Client().Reply(ErrNoSuchChannel(s, m.target))
			return
		}

		channel.Command(m)
		return
	}

	target := s.clients[m.target]
	if target == nil {
		m.Client().Reply(ErrNoSuchNick(s, m.target))
		return
	}
	target.Reply(RplPrivMsg(m.Client(), target, m.message))
	if target.away {
		m.Client().Reply(RplAway(s, target))
	}
}

func (m *ModeCommand) HandleServer(s *Server) {
	client := m.Client()
	target := s.clients[m.nickname]
	if client == target {
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

	client.Reply(ErrUsersDontMatch(s))
}

func (m *WhoisCommand) HandleServer(server *Server) {
	client := m.Client()

	// TODO implement target query

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
	channel.Command(msg)
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

func (msg *CapCommand) HandleServer(server *Server) {
	// TODO
}

func (msg *ProxyCommand) HandleServer(server *Server) {
	msg.Client().hostname = LookupHostname(msg.sourceIP)
}

func (msg *AwayCommand) HandleServer(server *Server) {
	client := msg.Client()
	client.away = msg.away
	client.awayMessage = msg.text

	if client.away {
		client.Reply(RplNowAway(server))
	} else {
		client.Reply(RplUnAway(server))
	}
}

func (msg *IsOnCommand) HandleServer(server *Server) {
	client := msg.Client()

	ison := make([]string, 0)
	for _, nick := range msg.nicks {
		if _, ok := server.clients[nick]; ok {
			ison = append(ison, nick)
		}
	}

	client.Reply(RplIsOn(server, ison))
}

func (msg *MOTDCommand) HandleServer(server *Server) {
	server.MOTD(msg.Client())
}

func (msg *NoticeCommand) HandleServer(server *Server) {
	if IsChannel(msg.target) {
		channel := server.channels[msg.target]
		if channel == nil {
			msg.Client().Reply(ErrNoSuchChannel(server, msg.target))
			return
		}

		channel.Command(msg)
		return
	}

	target := server.clients[msg.target]
	if target == nil {
		msg.Client().Reply(ErrNoSuchNick(server, msg.target))
		return
	}
	target.Reply(RplPrivMsg(msg.Client(), target, msg.message))
}
