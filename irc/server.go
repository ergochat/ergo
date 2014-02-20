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
	"strings"
	"time"
)

type Server struct {
	channels  ChannelNameMap
	clients   ClientNameMap
	commands  chan Command
	conns     chan net.Conn
	ctime     time.Time
	idle      chan *Client
	motdFile  string
	name      string
	operators map[string]string
	password  string
}

func NewServer(config *Config) *Server {
	server := &Server{
		channels:  make(ChannelNameMap),
		clients:   make(ClientNameMap),
		commands:  make(chan Command),
		conns:     make(chan net.Conn),
		ctime:     time.Now(),
		idle:      make(chan *Client),
		motdFile:  config.MOTD,
		name:      config.Name,
		operators: make(map[string]string),
		password:  config.Password,
	}

	for _, opConf := range config.Operators {
		server.operators[opConf.Name] = opConf.Password
	}

	for _, listenerConf := range config.Listeners {
		go server.listen(listenerConf)
	}

	return server
}

func (server *Server) ReceiveCommands() {
	for {
		select {
		case conn := <-server.conns:
			NewClient(server, conn)

		case client := <-server.idle:
			client.Idle()

		case cmd := <-server.commands:
			client := cmd.Client()
			if DEBUG_SERVER {
				log.Printf("%s → %s %s", client, server, cmd)
			}

			switch client.phase {
			case Authorization:
				authCmd, ok := cmd.(AuthServerCommand)
				if !ok {
					client.Quit("unexpected command")
					continue
				}
				authCmd.HandleAuthServer(server)

			case Registration:
				regCmd, ok := cmd.(RegServerCommand)
				if !ok {
					client.Quit("unexpected command")
					continue
				}
				regCmd.HandleRegServer(server)

			default:
				srvCmd, ok := cmd.(ServerCommand)
				if !ok {
					client.Reply(ErrUnknownCommand(server, cmd.Code()))
					continue
				}
				switch srvCmd.(type) {
				case *PingCommand, *PongCommand:
					client.Touch()
				case *QuitCommand:
					// no-op
				default:
					client.Active()
					client.Touch()
				}
				srvCmd.HandleServer(server)
			}
		}
	}
}

func (server *Server) InitPhase() Phase {
	if server.password == "" {
		return Registration
	}
	return Authorization
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
		log.Fatal(s, "listen error: ", err)
	}

	if DEBUG_SERVER {
		log.Printf("%s listening on %s", s, config.Address)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			if DEBUG_SERVER {
				log.Printf("%s accept error: %s", s, err)
			}
			continue
		}
		if DEBUG_SERVER {
			log.Printf("%s accept: %s", s, conn.RemoteAddr())
		}

		s.conns <- conn
	}
}

func (s *Server) GetOrMakeChannel(name string) *Channel {
	channel, ok := s.channels[name]

	if !ok {
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

//
// server functionality
//

func (s *Server) tryRegister(c *Client) {
	if c.HasNick() && c.HasUsername() {
		c.Register()
		c.Reply(RplWelcome(s, c))
		c.Reply(RplYourHost(s))
		c.Reply(RplCreated(s))
		c.Reply(RplMyInfo(s))
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
		line = strings.TrimRight(line, "\r\n")

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
// authorization commands
//

func (msg *ProxyCommand) HandleAuthServer(server *Server) {
	client := msg.Client()
	client.hostname = LookupHostname(msg.sourceIP)
}

func (msg *CapCommand) HandleAuthServer(server *Server) {
	// TODO
}

func (m *PassCommand) HandleAuthServer(s *Server) {
	client := m.Client()

	if s.password != m.password {
		client.Reply(ErrPasswdMismatch(s))
		client.socket.Close()
		return
	}

	client.phase = Registration
}

func (msg *QuitCommand) HandleAuthServer(server *Server) {
	msg.Client().Quit(msg.message)
}

//
// registration commands
//

func (m *NickCommand) HandleRegServer(s *Server) {
	client := m.Client()

	if m.nickname == "" {
		client.Reply(ErrNoNicknameGiven(s))
		return
	}

	if s.clients.Get(m.nickname) != nil {
		client.Reply(ErrNickNameInUse(s, m.nickname))
		return
	}

	if !IsNickname(m.nickname) {
		client.Reply(ErrErroneusNickname(s, m.nickname))
		return
	}

	client.SetNickname(m.nickname)
	s.tryRegister(client)
}

func (msg *RFC1459UserCommand) HandleRegServer(server *Server) {
	msg.HandleRegServer2(server)
}

func (msg *RFC2812UserCommand) HandleRegServer(server *Server) {
	client := msg.Client()
	flags := msg.Flags()
	if len(flags) > 0 {
		for _, mode := range msg.Flags() {
			client.flags[mode] = true
		}
		client.Reply(RplUModeIs(server, client))
	}
	msg.HandleRegServer2(server)
}

func (msg *UserCommand) HandleRegServer2(server *Server) {
	client := msg.Client()
	client.username, client.realname = msg.username, msg.realname
	server.tryRegister(client)
}

func (msg *QuitCommand) HandleRegServer(server *Server) {
	msg.Client().Quit(msg.message)
}

//
// normal commands
//

func (m *PassCommand) HandleServer(s *Server) {
	m.Client().Reply(ErrAlreadyRegistered(s))
}

func (m *PingCommand) HandleServer(s *Server) {
	m.Client().Reply(RplPong(s, m.Client()))
}

func (m *PongCommand) HandleServer(s *Server) {
	// no-op
}

func (msg *NickCommand) HandleServer(server *Server) {
	client := msg.Client()

	if msg.nickname == "" {
		client.Reply(ErrNoNicknameGiven(server))
		return
	}

	if server.clients.Get(msg.nickname) != nil {
		client.Reply(ErrNickNameInUse(server, msg.nickname))
		return
	}

	client.ChangeNickname(msg.nickname)
}

func (m *UserCommand) HandleServer(s *Server) {
	m.Client().Reply(ErrAlreadyRegistered(s))
}

func (msg *QuitCommand) HandleServer(server *Server) {
	msg.Client().Quit(msg.message)
}

func (m *JoinCommand) HandleServer(s *Server) {
	client := m.Client()

	if m.zero {
		for channel := range client.channels {
			channel.Part(client, client.Nick())
		}
		return
	}

	for name, key := range m.channels {
		channel := s.GetOrMakeChannel(name)
		channel.Join(client, key)
	}
}

func (m *PartCommand) HandleServer(server *Server) {
	client := m.Client()
	for _, chname := range m.channels {
		channel := server.channels[chname]

		if channel == nil {
			m.Client().Reply(ErrNoSuchChannel(server, chname))
			continue
		}

		channel.Part(client, m.Message())
	}
}

func (msg *TopicCommand) HandleServer(server *Server) {
	client := msg.Client()
	channel := server.channels[msg.channel]
	if channel == nil {
		client.Reply(ErrNoSuchChannel(server, msg.channel))
		return
	}

	if msg.setTopic {
		channel.SetTopic(client, msg.topic)
	} else {
		channel.GetTopic(client)
	}
}

func (msg *PrivMsgCommand) HandleServer(server *Server) {
	client := msg.Client()
	if IsChannel(msg.target) {
		channel := server.channels[msg.target]
		if channel == nil {
			client.Reply(ErrNoSuchChannel(server, msg.target))
			return
		}

		channel.PrivMsg(client, msg.message)
		return
	}

	target := server.clients[msg.target]
	if target == nil {
		client.Reply(ErrNoSuchNick(server, msg.target))
		return
	}
	target.Reply(RplPrivMsg(client, target, msg.message))
	if target.flags[Away] {
		client.Reply(RplAway(server, target))
	}
}

func (m *ModeCommand) HandleServer(s *Server) {
	client := m.Client()
	target := s.clients.Get(m.nickname)

	if target == nil {
		client.Reply(ErrNoSuchNick(s, m.nickname))
		return
	}

	if client != target && !client.flags[Operator] {
		client.Reply(ErrUsersDontMatch(s))
		return
	}

	changes := make(ModeChanges, 0)

	for _, change := range m.changes {
		switch change.mode {
		case Invisible, ServerNotice, WallOps:
			switch change.op {
			case Add:
				client.flags[change.mode] = true
				changes = append(changes, change)

			case Remove:
				delete(client.flags, change.mode)
				changes = append(changes, change)
			}

		case Operator, LocalOperator:
			if change.op == Remove {
				delete(client.flags, change.mode)
				changes = append(changes, change)
			}
		}
	}

	if len(changes) > 0 {
		client.Reply(RplMode(client, changes))
	}
}

func (m *WhoisCommand) HandleServer(server *Server) {
	client := m.Client()

	// TODO implement target query

	for _, mask := range m.masks {
		// TODO implement wildcard matching
		mclient := server.clients.Get(mask)
		if mclient == nil {
			client.Reply(ErrNoSuchNick(server, mask))
			continue
		}
		client.Reply(RplWhoisUser(mclient))
		if client.flags[Operator] {
			client.Reply(RplWhoisOperator(mclient))
		}
		client.Reply(RplWhoisIdle(mclient))
		client.Reply(NewWhoisChannelsReply(mclient))
		client.Reply(RplEndOfWhois(server))
	}
}

func (msg *ChannelModeCommand) HandleServer(server *Server) {
	client := msg.Client()
	channel := server.channels[msg.channel]
	if channel == nil {
		client.Reply(ErrNoSuchChannel(server, msg.channel))
		return
	}

	channel.Mode(client, msg.changes)
}

func whoChannel(client *Client, channel *Channel) {
	for member := range channel.members {
		if !client.flags[Invisible] {
			client.Reply(RplWhoReply(channel, member))
		}
	}
}

func (msg *WhoCommand) HandleServer(server *Server) {
	client := msg.Client()
	// TODO implement wildcard matching

	mask := string(msg.mask)
	if mask == "" {
		for _, channel := range server.channels {
			whoChannel(client, channel)
		}
	} else if IsChannel(mask) {
		channel := server.channels[mask]
		if channel != nil {
			whoChannel(client, channel)
		}
	} else {
		mclient := server.clients[mask]
		if mclient != nil && !mclient.flags[Invisible] {
			client.Reply(RplWhoReply(nil, mclient))
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

	client.flags[Operator] = true

	client.Reply(RplYoureOper(server))
	client.Reply(RplUModeIs(server, client))
}

func (msg *AwayCommand) HandleServer(server *Server) {
	client := msg.Client()
	if msg.away {
		client.flags[Away] = true
	} else {
		delete(client.flags, Away)
	}
	client.awayMessage = msg.text

	if client.flags[Away] {
		client.Reply(RplNowAway(server))
	} else {
		client.Reply(RplUnAway(server))
	}
}

func (msg *IsOnCommand) HandleServer(server *Server) {
	client := msg.Client()

	ison := make([]string, 0)
	for _, nick := range msg.nicks {
		if iclient := server.clients.Get(nick); iclient != nil {
			ison = append(ison, iclient.Nick())
		}
	}

	client.Reply(RplIsOn(server, ison))
}

func (msg *MOTDCommand) HandleServer(server *Server) {
	server.MOTD(msg.Client())
}

func (msg *NoticeCommand) HandleServer(server *Server) {
	client := msg.Client()
	if IsChannel(msg.target) {
		channel := server.channels[msg.target]
		if channel == nil {
			client.Reply(ErrNoSuchChannel(server, msg.target))
			return
		}

		channel.Notice(client, msg.message)
		return
	}

	target := server.clients.Get(msg.target)
	if target == nil {
		client.Reply(ErrNoSuchNick(server, msg.target))
		return
	}
	target.Reply(RplNotice(client, target, msg.message))
}

func (msg *KickCommand) HandleServer(server *Server) {
	client := msg.Client()
	for chname, nickname := range msg.kicks {
		channel := server.channels[chname]
		if channel == nil {
			client.Reply(ErrNoSuchChannel(server, chname))
			continue
		}

		target := server.clients[nickname]
		if target == nil {
			client.Reply(ErrNoSuchNick(server, nickname))
			continue
		}

		channel.Kick(client, target, msg.Comment())
	}
}

func (msg *ListCommand) HandleServer(server *Server) {
	client := msg.Client()

	// TODO target server
	if msg.target != "" {
		client.Reply(ErrNoSuchServer(server, msg.target))
		return
	}

	if len(msg.channels) == 0 {
		for _, channel := range server.channels {
			if !client.flags[Operator] &&
				(channel.flags[Secret] || channel.flags[Private]) {
				continue
			}
			client.Reply(RplList(channel))
		}
	} else {
		for _, chname := range msg.channels {
			channel := server.channels[chname]
			if channel == nil || (!client.flags[Operator] &&
				(channel.flags[Secret] || channel.flags[Private])) {
				client.Reply(ErrNoSuchChannel(server, chname))
				continue
			}
			client.Reply(RplList(channel))
		}
	}
	client.Reply(RplListEnd(server))
}

func (msg *NamesCommand) HandleServer(server *Server) {
	client := msg.Client()
	if len(server.channels) == 0 {
		for _, channel := range server.channels {
			channel.Names(client)
		}
		return
	}

	for _, chname := range msg.channels {
		channel := server.channels[chname]
		if channel == nil {
			client.Reply(ErrNoSuchChannel(server, chname))
			continue
		}
		channel.Names(client)
	}
}
