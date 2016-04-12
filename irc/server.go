package irc

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type ServerCommand interface {
	Command
	HandleServer(*Server)
}

type RegServerCommand interface {
	Command
	HandleRegServer(*Server)
}

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
	theaters  map[Name][]byte
}

var (
	SERVER_SIGNALS = []os.Signal{syscall.SIGINT, syscall.SIGHUP,
		syscall.SIGTERM, syscall.SIGQUIT}
)

func NewServer(config *Config) *Server {
	server := &Server{
		channels:  make(ChannelNameMap),
		clients:   NewClientLookupSet(),
		commands:  make(chan Command),
		ctime:     time.Now(),
		db:        OpenDB(config.Server.Database),
		idle:      make(chan *Client),
		motdFile:  config.Server.MOTD,
		name:      NewName(config.Server.Name),
		newConns:  make(chan net.Conn),
		operators: config.Operators(),
		signals:   make(chan os.Signal, len(SERVER_SIGNALS)),
		whoWas:    NewWhoWasList(100),
		theaters:  config.Theaters(),
	}

	if config.Server.Password != "" {
		server.password = config.Server.PasswordBytes()
	}

	server.loadChannels()

	for _, addr := range config.Server.Listen {
		server.listen(addr)
	}

	if config.Server.Wslisten != "" {
		server.wslisten(config.Server.Wslisten)
	}

	signal.Notify(server.signals, SERVER_SIGNALS...)

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
		var name, flags, key, topic string
		var userLimit uint64
		var banList, exceptList, inviteList string
		err = rows.Scan(&name, &flags, &key, &topic, &userLimit, &banList,
			&exceptList, &inviteList)
		if err != nil {
			log.Println("Server.loadChannels:", err)
			continue
		}

		channel := NewChannel(server, NewName(name))
		for _, flag := range flags {
			channel.flags[ChannelMode(flag)] = true
		}
		channel.key = NewText(key)
		channel.topic = NewText(topic)
		channel.userLimit = userLimit
		loadChannelList(channel, banList, BanMask)
		loadChannelList(channel, exceptList, ExceptMask)
		loadChannelList(channel, inviteList, InviteMask)
	}
}

func (server *Server) processCommand(cmd Command) {
	client := cmd.Client()

	if !client.registered {
		regCmd, ok := cmd.(RegServerCommand)
		if !ok {
			client.Quit("unexpected command")
			return
		}
		regCmd.HandleRegServer(server)
		return
	}

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

	Log.info.Printf("%s listening on %s", s, addr)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				Log.error.Printf("%s accept error: %s", s, err)
				continue
			}
			Log.debug.Printf("%s accept: %s", s, conn.RemoteAddr())

			s.newConns <- conn
		}
	}()
}

//
// websocket listen goroutine
//

func (s *Server) wslisten(addr string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			Log.error.Printf("%s method not allowed", s)
			return
		}

		// We don't have any subprotocols, so if someone attempts to `new
		// WebSocket(server, "subprotocol")` they'll break here, instead of
		// getting the default, ambiguous, response from gorilla.
		if v, ok := r.Header["Sec-Websocket-Protocol"]; ok {
			http.Error(w, fmt.Sprintf("WebSocket subprocotols (e.g. %s) not supported", v), 400)
		}

		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			Log.error.Printf("%s websocket upgrade error: %s", s, err)
			return
		}

		s.newConns <- WSContainer{ws}
	})
	go func() {
		Log.info.Printf("%s listening on %s", s, addr)
		err := http.ListenAndServe(addr, nil)
		if err != nil {
			Log.error.Printf("%s listenAndServe error: %s", s, err)
		}
	}()
}

//
// server functionality
//

func (s *Server) tryRegister(c *Client) {
	if c.registered || !c.HasNick() || !c.HasUsername() ||
		(c.capState == CapNegotiating) {
		return
	}

	c.Register()
	c.RplWelcome()
	c.RplYourHost()
	c.RplCreated()
	c.RplMyInfo()
	s.MOTD(c)
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

		client.RplMOTD(line)
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

func (server *Server) Reply(target *Client, message string) {
	target.Reply(RplPrivMsg(server, target, NewText(message)))
}

func (server *Server) Replyf(target *Client, format string, args ...interface{}) {
	server.Reply(target, fmt.Sprintf(format, args...))
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
		for _, mode := range flags {
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
	client := m.Client()
	client.Reply(RplPong(client, m.server.Text()))
}

func (m *PongCommand) HandleServer(s *Server) {
	// no-op
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
	client.Reply(RplModeChanges(client, client, ModeChanges{&ModeChange{
		mode: Operator,
		op:   Add,
	}}))
}

func (msg *AwayCommand) HandleServer(server *Server) {
	client := msg.Client()
	if len(msg.text) > 0 {
		client.flags[Away] = true
	} else {
		delete(client.flags, Away)
	}
	client.awayMessage = msg.text

	var op ModeOp
	if client.flags[Away] {
		op = Add
		client.RplNowAway()
	} else {
		op = Remove
		client.RplUnAway()
	}
	client.Reply(RplModeChanges(client, client, ModeChanges{&ModeChange{
		mode: Away,
		op:   op,
	}}))
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
