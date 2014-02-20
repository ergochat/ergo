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
	ctime     time.Time
	hostnames chan *HostnameLookup
	idle      chan *Client
	motdFile  string
	name      string
	newConns  chan net.Conn
	operators map[string]string
	password  string
}

func NewServer(config *Config) *Server {
	server := &Server{
		channels:  make(ChannelNameMap),
		clients:   make(ClientNameMap),
		commands:  make(chan Command, 16),
		ctime:     time.Now(),
		hostnames: make(chan *HostnameLookup, 16),
		idle:      make(chan *Client, 16),
		motdFile:  config.MOTD,
		name:      config.Name,
		newConns:  make(chan net.Conn, 16),
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
		case conn := <-server.newConns:
			NewClient(server, conn)

		case lookup := <-server.hostnames:
			if DEBUG_SERVER {
				log.Printf("%s setting hostname of %s to %s",
					server, lookup.client, lookup.hostname)
			}
			lookup.client.hostname = lookup.hostname

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
					client.ErrUnknownCommand(cmd.Code())
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

//
// listen goroutine
//

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

		s.newConns <- conn
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
		c.RplWelcome()
		c.RplYourHost()
		c.RplCreated()
		c.RplMyInfo()
		s.MOTD(c)
	}
}

func (server *Server) MOTD(client *Client) {
	if server.motdFile == "" {
		client.ErrNoMOTD()
		return
	}

	file, err := os.Open(server.motdFile)
	if err != nil {
		client.ErrNoMOTD()
		return
	}
	defer file.Close()

	client.RplMOTDStart()
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")

		if len(line) > 80 {
			for len(line) > 80 {
				client.RplMOTD(line[0:80])
				line = line[80:]
			}
			if len(line) > 0 {
				client.RplMOTD(line)
			}
		} else {
			client.RplMOTD(line)
		}
	}
	client.RplMOTDEnd()
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
	go msg.Client().LookupHostname(msg.sourceIP)
}

func (msg *CapCommand) HandleAuthServer(server *Server) {
	// TODO
}

func (m *PassCommand) HandleAuthServer(s *Server) {
	client := m.Client()

	if s.password != m.password {
		client.ErrPasswdMismatch()
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
		client.ErrNoNicknameGiven()
		return
	}

	if s.clients.Get(m.nickname) != nil {
		client.ErrNickNameInUse(m.nickname)
		return
	}

	if !IsNickname(m.nickname) {
		client.ErrErroneusNickname(m.nickname)
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
		client.RplUModeIs(client)
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
	m.Client().ErrAlreadyRegistered()
}

func (m *PingCommand) HandleServer(s *Server) {
	m.Client().replies <- RplPong(s, m.Client())
}

func (m *PongCommand) HandleServer(s *Server) {
	// no-op
}

func (msg *NickCommand) HandleServer(server *Server) {
	client := msg.Client()

	if msg.nickname == "" {
		client.ErrNoNicknameGiven()
		return
	}

	if server.clients.Get(msg.nickname) != nil {
		client.ErrNickNameInUse(msg.nickname)
		return
	}

	client.ChangeNickname(msg.nickname)
}

func (m *UserCommand) HandleServer(s *Server) {
	m.Client().ErrAlreadyRegistered()
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
			m.Client().ErrNoSuchChannel(chname)
			continue
		}

		channel.Part(client, m.Message())
	}
}

func (msg *TopicCommand) HandleServer(server *Server) {
	client := msg.Client()
	channel := server.channels[msg.channel]
	if channel == nil {
		client.ErrNoSuchChannel(msg.channel)
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
			client.ErrNoSuchChannel(msg.target)
			return
		}

		channel.PrivMsg(client, msg.message)
		return
	}

	target := server.clients[msg.target]
	if target == nil {
		client.ErrNoSuchNick(msg.target)
		return
	}
	target.replies <- RplPrivMsg(client, target, msg.message)
	if target.flags[Away] {
		target.RplAway(client)
	}
}

func (m *ModeCommand) HandleServer(s *Server) {
	client := m.Client()
	target := s.clients.Get(m.nickname)

	if target == nil {
		client.ErrNoSuchNick(m.nickname)
		return
	}

	if client != target && !client.flags[Operator] {
		client.ErrUsersDontMatch()
		return
	}

	changes := make(ModeChanges, 0)

	for _, change := range m.changes {
		switch change.mode {
		case Invisible, ServerNotice, WallOps:
			switch change.op {
			case Add:
				target.flags[change.mode] = true
				changes = append(changes, change)

			case Remove:
				delete(target.flags, change.mode)
				changes = append(changes, change)
			}

		case Operator, LocalOperator:
			if change.op == Remove {
				delete(target.flags, change.mode)
				changes = append(changes, change)
			}
		}
	}

	// Who should get these replies?
	if len(changes) > 0 {
		client.replies <- RplMode(client, target, changes)
	}
}

func (client *Client) WhoisChannelsNames() []string {
	chstrs := make([]string, len(client.channels))
	index := 0
	for channel := range client.channels {
		switch {
		case channel.members[client][ChannelOperator]:
			chstrs[index] = "@" + channel.name

		case channel.members[client][Voice]:
			chstrs[index] = "+" + channel.name

		default:
			chstrs[index] = channel.name
		}
		index += 1
	}
	return chstrs
}

func (m *WhoisCommand) HandleServer(server *Server) {
	client := m.Client()

	// TODO implement target query

	for _, mask := range m.masks {
		// TODO implement wildcard matching
		mclient := server.clients.Get(mask)
		if mclient == nil {
			client.ErrNoSuchNick(mask)
			continue
		}
		client.RplWhoisUser(mclient)
		if client.flags[Operator] {
			client.RplWhoisOperator(mclient)
		}
		client.RplWhoisIdle(mclient)
		client.MultilineReply(client.WhoisChannelsNames(), RPL_WHOISCHANNELS,
			"%s :%s", client.Nick())
		client.RplEndOfWhois()
	}
}

func (msg *ChannelModeCommand) HandleServer(server *Server) {
	client := msg.Client()
	channel := server.channels[msg.channel]
	if channel == nil {
		client.ErrNoSuchChannel(msg.channel)
		return
	}

	channel.Mode(client, msg.changes)
}

func whoChannel(client *Client, channel *Channel) {
	for member := range channel.members {
		if !client.flags[Invisible] {
			client.RplWhoReply(channel, member)
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
			client.RplWhoReply(nil, mclient)
		}
	}

	client.RplEndOfWho(mask)
}

func (msg *OperCommand) HandleServer(server *Server) {
	client := msg.Client()

	if server.operators[msg.name] != msg.password {
		client.ErrPasswdMismatch()
		return
	}

	client.flags[Operator] = true

	client.RplYoureOper()
	client.RplUModeIs(client)
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
		client.RplNowAway()
	} else {
		client.RplUnAway()
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

	client.RplIsOn(ison)
}

func (msg *MOTDCommand) HandleServer(server *Server) {
	server.MOTD(msg.Client())
}

func (msg *NoticeCommand) HandleServer(server *Server) {
	client := msg.Client()
	if IsChannel(msg.target) {
		channel := server.channels[msg.target]
		if channel == nil {
			client.ErrNoSuchChannel(msg.target)
			return
		}

		channel.Notice(client, msg.message)
		return
	}

	target := server.clients.Get(msg.target)
	if target == nil {
		client.ErrNoSuchNick(msg.target)
		return
	}
	target.replies <- RplNotice(client, target, msg.message)
}

func (msg *KickCommand) HandleServer(server *Server) {
	client := msg.Client()
	for chname, nickname := range msg.kicks {
		channel := server.channels[chname]
		if channel == nil {
			client.ErrNoSuchChannel(chname)
			continue
		}

		target := server.clients[nickname]
		if target == nil {
			client.ErrNoSuchNick(nickname)
			continue
		}

		channel.Kick(client, target, msg.Comment())
	}
}

func (msg *ListCommand) HandleServer(server *Server) {
	client := msg.Client()

	// TODO target server
	if msg.target != "" {
		client.ErrNoSuchServer(msg.target)
		return
	}

	if len(msg.channels) == 0 {
		for _, channel := range server.channels {
			if !client.flags[Operator] &&
				(channel.flags[Secret] || channel.flags[Private]) {
				continue
			}
			client.RplList(channel)
		}
	} else {
		for _, chname := range msg.channels {
			channel := server.channels[chname]
			if channel == nil || (!client.flags[Operator] &&
				(channel.flags[Secret] || channel.flags[Private])) {
				client.ErrNoSuchChannel(chname)
				continue
			}
			client.RplList(channel)
		}
	}
	client.RplListEnd(server)
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
			client.ErrNoSuchChannel(chname)
			continue
		}
		channel.Names(client)
	}
}
