package irc

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"
)

type Server struct {
	channels  ChannelNameMap
	clients   *ClientLookupSet
	commands  chan Command
	ctime     time.Time
	db        *sql.DB
	idle      chan *Client
	motdFile  string
	name      Name
	newConns  chan net.Conn
	operators map[Name][]byte
	password  []byte
	signals   chan os.Signal
	whoWas    *WhoWasList
}

func NewServer(config *Config) *Server {
	server := &Server{
		channels:  make(ChannelNameMap),
		clients:   NewClientLookupSet(),
		commands:  make(chan Command, 16),
		ctime:     time.Now(),
		db:        OpenDB(config.Server.Database),
		idle:      make(chan *Client, 16),
		motdFile:  config.Server.MOTD,
		name:      NewName(config.Server.Name),
		newConns:  make(chan net.Conn, 16),
		operators: config.Operators(),
		signals:   make(chan os.Signal, 1),
		whoWas:    NewWhoWasList(100),
	}

	if config.Server.Password != "" {
		server.password = config.Server.PasswordBytes()
	}

	server.loadChannels()

	for _, addr := range config.Server.Listen {
		go server.listen(addr)
	}

	signal.Notify(server.signals, syscall.SIGINT, syscall.SIGHUP,
		syscall.SIGTERM, syscall.SIGQUIT)

	return server
}

func loadChannelList(channel *Channel, list string, maskMode ChannelMode) {
	if list == "" {
		return
	}
	channel.lists[maskMode].AddAll(NewNames(strings.Split(list, " ")))
}

func (server *Server) loadChannels() {
	rows, err := server.db.Query(`
        SELECT name, flags, key, topic, user_limit, ban_list, except_list,
               invite_list
          FROM channel`)
	if err != nil {
		log.Fatal("error loading channels: ", err)
	}
	for rows.Next() {
		var name Name
		var flags string
		var key, topic Text
		var userLimit uint64
		var banList, exceptList, inviteList string
		err = rows.Scan(&name, &flags, &key, &topic, &userLimit, &banList,
			&exceptList, &inviteList)
		if err != nil {
			log.Println("Server.loadChannels:", err)
			continue
		}

		channel := NewChannel(server, name)
		for _, flag := range flags {
			channel.flags[ChannelMode(flag)] = true
		}
		channel.key = key
		channel.topic = topic
		channel.userLimit = userLimit
		loadChannelList(channel, banList, BanMask)
		loadChannelList(channel, exceptList, ExceptMask)
		loadChannelList(channel, inviteList, InviteMask)
	}
}

func (server *Server) processCommand(cmd Command) {
	client := cmd.Client()
	if DEBUG_SERVER {
		log.Printf("%s → %s %s", client, server, cmd)
	}

	switch client.phase {
	case Registration:
		regCmd, ok := cmd.(RegServerCommand)
		if !ok {
			client.Quit("unexpected command")
			return
		}
		regCmd.HandleRegServer(server)

	case Normal:
		srvCmd, ok := cmd.(ServerCommand)
		if !ok {
			client.ErrUnknownCommand(cmd.Code())
			return
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

func (server *Server) Shutdown() {
	server.db.Close()
	for _, client := range server.clients.byNick {
		client.Reply(RplNotice(server, client, "shutting down"))
	}
}

func (server *Server) Run() {
	done := false
	for !done {
		select {
		case <-server.signals:
			server.Shutdown()
			done = true

		case conn := <-server.newConns:
			NewClient(server, conn)

		case cmd := <-server.commands:
			server.processCommand(cmd)

		case client := <-server.idle:
			client.Idle()
		}
	}
}

//
// listen goroutine
//

func (s *Server) listen(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(s, "listen error: ", err)
	}

	if DEBUG_SERVER {
		log.Printf("%s listening on %s", s, addr)
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

//
// server functionality
//

func (s *Server) tryRegister(c *Client) {
	if c.HasNick() && c.HasUsername() && (c.capState != CapNegotiating) {
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

func (s *Server) Id() Name {
	return s.name
}

func (s *Server) String() string {
	return s.name.String()
}

func (s *Server) Nick() Name {
	return s.Id()
}

//
// registration commands
//

func (msg *PassCommand) HandleRegServer(server *Server) {
	client := msg.Client()
	if msg.err != nil {
		client.ErrPasswdMismatch()
		client.Quit("bad password")
		return
	}

	client.authorized = true
}

func (msg *ProxyCommand) HandleRegServer(server *Server) {
	msg.Client().hostname = msg.hostname
}

func (msg *CapCommand) HandleRegServer(server *Server) {
	client := msg.Client()

	switch msg.subCommand {
	case CAP_LS:
		client.capState = CapNegotiating
		client.Reply(RplCap(client, CAP_LS, SupportedCapabilities))

	case CAP_LIST:
		client.Reply(RplCap(client, CAP_LIST, client.capabilities))

	case CAP_REQ:
		client.capState = CapNegotiating
		for capability := range msg.capabilities {
			if !SupportedCapabilities[capability] {
				client.Reply(RplCap(client, CAP_NAK, msg.capabilities))
				return
			}
		}
		for capability := range msg.capabilities {
			client.capabilities[capability] = true
		}
		client.Reply(RplCap(client, CAP_ACK, msg.capabilities))

	case CAP_CLEAR:
		reply := RplCap(client, CAP_ACK, client.capabilities.DisableString())
		client.capabilities = make(CapabilitySet)
		client.Reply(reply)

	case CAP_END:
		client.capState = CapNegotiated
		server.tryRegister(client)

	default:
		client.ErrInvalidCapCmd(msg.subCommand)
	}
}

func (m *NickCommand) HandleRegServer(s *Server) {
	client := m.Client()
	if !client.authorized {
		client.ErrPasswdMismatch()
		client.Quit("bad password")
		return
	}

	if client.capState == CapNegotiating {
		client.capState = CapNegotiated
	}

	if m.nickname == "" {
		client.ErrNoNicknameGiven()
		return
	}

	if s.clients.Get(m.nickname) != nil {
		client.ErrNickNameInUse(m.nickname)
		return
	}

	if !m.nickname.IsNickname() {
		client.ErrErroneusNickname(m.nickname)
		return
	}

	client.SetNickname(m.nickname)
	s.tryRegister(client)
}

func (msg *RFC1459UserCommand) HandleRegServer(server *Server) {
	client := msg.Client()
	if !client.authorized {
		client.ErrPasswdMismatch()
		client.Quit("bad password")
		return
	}
	msg.setUserInfo(server)
}

func (msg *RFC2812UserCommand) HandleRegServer(server *Server) {
	client := msg.Client()
	if !client.authorized {
		client.ErrPasswdMismatch()
		client.Quit("bad password")
		return
	}
	flags := msg.Flags()
	if len(flags) > 0 {
		for _, mode := range msg.Flags() {
			client.flags[mode] = true
		}
		client.RplUModeIs(client)
	}
	msg.setUserInfo(server)
}

func (msg *UserCommand) setUserInfo(server *Server) {
	client := msg.Client()
	if client.capState == CapNegotiating {
		client.capState = CapNegotiated
	}

	server.clients.Remove(client)
	client.username, client.realname = msg.username, msg.realname
	server.clients.Add(client)

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
	m.Client().Reply(RplPong(m.Client()))
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

	if !msg.nickname.IsNickname() {
		client.ErrErroneusNickname(msg.nickname)
		return
	}

	if msg.nickname == client.nick {
		return
	}

	target := server.clients.Get(msg.nickname)
	if (target != nil) && (target != client) {
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
			channel.Part(client, client.Nick().Text())
		}
		return
	}

	for name, key := range m.channels {
		if !name.IsChannel() {
			client.ErrNoSuchChannel(name)
			continue
		}

		channel := s.channels.Get(name)
		if channel == nil {
			channel = NewChannel(s, name)
		}
		channel.Join(client, key)
	}
}

func (m *PartCommand) HandleServer(server *Server) {
	client := m.Client()
	for _, chname := range m.channels {
		channel := server.channels.Get(chname)

		if channel == nil {
			m.Client().ErrNoSuchChannel(chname)
			continue
		}

		channel.Part(client, m.Message())
	}
}

func (msg *TopicCommand) HandleServer(server *Server) {
	client := msg.Client()
	channel := server.channels.Get(msg.channel)
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
	if msg.target.IsChannel() {
		channel := server.channels.Get(msg.target)
		if channel == nil {
			client.ErrNoSuchChannel(msg.target)
			return
		}

		channel.PrivMsg(client, msg.message)
		return
	}

	target := server.clients.Get(msg.target)
	if target == nil {
		client.ErrNoSuchNick(msg.target)
		return
	}
	target.Reply(RplPrivMsg(client, target, msg.message))
	if target.flags[Away] {
		client.RplAway(target)
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

	changes := make(ModeChanges, 0, len(m.changes))

	for _, change := range m.changes {
		switch change.mode {
		case Invisible, ServerNotice, WallOps:
			switch change.op {
			case Add:
				if target.flags[change.mode] {
					continue
				}
				target.flags[change.mode] = true
				changes = append(changes, change)

			case Remove:
				if !target.flags[change.mode] {
					continue
				}
				delete(target.flags, change.mode)
				changes = append(changes, change)
			}

		case Operator, LocalOperator:
			if change.op == Remove {
				if !target.flags[change.mode] {
					continue
				}
				delete(target.flags, change.mode)
				changes = append(changes, change)
			}
		}
	}

	// Who should get these replies?
	if len(changes) > 0 {
		client.Reply(RplMode(client, target, changes))
	}
}

func (client *Client) WhoisChannelsNames() []string {
	chstrs := make([]string, len(client.channels))
	index := 0
	for channel := range client.channels {
		switch {
		case channel.members[client][ChannelOperator]:
			chstrs[index] = "@" + channel.name.String()

		case channel.members[client][Voice]:
			chstrs[index] = "+" + channel.name.String()

		default:
			chstrs[index] = channel.name.String()
		}
		index += 1
	}
	return chstrs
}

func (m *WhoisCommand) HandleServer(server *Server) {
	client := m.Client()

	// TODO implement target query

	for _, mask := range m.masks {
		matches := server.clients.FindAll(mask)
		if len(matches) == 0 {
			client.ErrNoSuchNick(mask)
			continue
		}
		for mclient := range matches {
			client.RplWhois(mclient)
		}
	}
}

func (msg *ChannelModeCommand) HandleServer(server *Server) {
	client := msg.Client()
	channel := server.channels.Get(msg.channel)
	if channel == nil {
		client.ErrNoSuchChannel(msg.channel)
		return
	}

	channel.Mode(client, msg.changes)
}

func whoChannel(client *Client, channel *Channel, friends ClientSet) {
	for member := range channel.members {
		if !client.flags[Invisible] || friends[client] {
			client.RplWhoReply(channel, member)
		}
	}
}

func (msg *WhoCommand) HandleServer(server *Server) {
	client := msg.Client()
	friends := client.Friends()
	mask := msg.mask

	if mask == "" {
		for _, channel := range server.channels {
			whoChannel(client, channel, friends)
		}
	} else if mask.IsChannel() {
		// TODO implement wildcard matching
		channel := server.channels.Get(mask)
		if channel != nil {
			whoChannel(client, channel, friends)
		}
	} else {
		for mclient := range server.clients.FindAll(mask) {
			client.RplWhoReply(nil, mclient)
		}
	}

	client.RplEndOfWho(mask)
}

func (msg *OperCommand) HandleServer(server *Server) {
	client := msg.Client()

	if (msg.hash == nil) || (msg.err != nil) {
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
			ison = append(ison, iclient.Nick().String())
		}
	}

	client.RplIsOn(ison)
}

func (msg *MOTDCommand) HandleServer(server *Server) {
	server.MOTD(msg.Client())
}

func (msg *NoticeCommand) HandleServer(server *Server) {
	client := msg.Client()
	if msg.target.IsChannel() {
		channel := server.channels.Get(msg.target)
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
	target.Reply(RplNotice(client, target, msg.message))
}

func (msg *KickCommand) HandleServer(server *Server) {
	client := msg.Client()
	for chname, nickname := range msg.kicks {
		channel := server.channels.Get(chname)
		if channel == nil {
			client.ErrNoSuchChannel(chname)
			continue
		}

		target := server.clients.Get(nickname)
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
			if !client.flags[Operator] && channel.flags[Private] {
				continue
			}
			client.RplList(channel)
		}
	} else {
		for _, chname := range msg.channels {
			channel := server.channels.Get(chname)
			if channel == nil || (!client.flags[Operator] && channel.flags[Private]) {
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
		channel := server.channels.Get(chname)
		if channel == nil {
			client.ErrNoSuchChannel(chname)
			continue
		}
		channel.Names(client)
	}
}

func (server *Server) Reply(target *Client, format string, args ...interface{}) {
	target.Reply(RplPrivMsg(server, target, NewText(fmt.Sprintf(format, args...))))
}

func (msg *DebugCommand) HandleServer(server *Server) {
	client := msg.Client()
	if !client.flags[Operator] {
		return
	}

	switch msg.subCommand {
	case "GC":
		runtime.GC()
		server.Reply(client, "OK")

	case "GCSTATS":
		stats := &debug.GCStats{
			PauseQuantiles: make([]time.Duration, 5),
		}
		server.Reply(client, "last GC:     %s", stats.LastGC.Format(time.RFC1123))
		server.Reply(client, "num GC:      %d", stats.NumGC)
		server.Reply(client, "pause total: %s", stats.PauseTotal)
		server.Reply(client, "pause quantiles min%%: %s", stats.PauseQuantiles[0])
		server.Reply(client, "pause quantiles 25%%:  %s", stats.PauseQuantiles[1])
		server.Reply(client, "pause quantiles 50%%:  %s", stats.PauseQuantiles[2])
		server.Reply(client, "pause quantiles 75%%:  %s", stats.PauseQuantiles[3])
		server.Reply(client, "pause quantiles max%%: %s", stats.PauseQuantiles[4])

	case "NUMGOROUTINE":
		count := runtime.NumGoroutine()
		server.Reply(client, "num goroutines: %d", count)

	case "PROFILEHEAP":
		file, err := os.Create("ergonomadic.heap.prof")
		if err != nil {
			log.Printf("error: %s", err)
			break
		}
		defer file.Close()
		pprof.Lookup("heap").WriteTo(file, 0)
		server.Reply(client, "written to ergonomadic-heap.prof")
	}
}

func (msg *VersionCommand) HandleServer(server *Server) {
	client := msg.Client()
	if (msg.target != "") && (msg.target != server.name) {
		client.ErrNoSuchServer(msg.target)
		return
	}

	client.RplVersion()
}

func (msg *InviteCommand) HandleServer(server *Server) {
	client := msg.Client()

	target := server.clients.Get(msg.nickname)
	if target == nil {
		client.ErrNoSuchNick(msg.nickname)
		return
	}

	channel := server.channels.Get(msg.channel)
	if channel == nil {
		client.RplInviting(target, msg.channel)
		target.Reply(RplInviteMsg(client, target, msg.channel))
		return
	}

	channel.Invite(target, client)
}

func (msg *TimeCommand) HandleServer(server *Server) {
	client := msg.Client()
	if (msg.target != "") && (msg.target != server.name) {
		client.ErrNoSuchServer(msg.target)
		return
	}
	client.RplTime()
}

func (msg *KillCommand) HandleServer(server *Server) {
	client := msg.Client()
	if !client.flags[Operator] {
		client.ErrNoPrivileges()
		return
	}

	target := server.clients.Get(msg.nickname)
	if target == nil {
		client.ErrNoSuchNick(msg.nickname)
		return
	}

	quitMsg := fmt.Sprintf("KILLed by %s: %s", client.Nick(), msg.comment)
	target.Quit(NewText(quitMsg))
}

func (msg *WhoWasCommand) HandleServer(server *Server) {
	client := msg.Client()
	for _, nickname := range msg.nicknames {
		results := server.whoWas.Find(nickname, msg.count)
		if len(results) == 0 {
			client.ErrWasNoSuchNick(nickname)
		} else {
			for _, whoWas := range results {
				client.RplWhoWasUser(whoWas)
			}
		}
		client.RplEndOfWhoWas(nickname)
	}
}
