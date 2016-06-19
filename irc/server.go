// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"bufio"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/DanielOaks/girc-go/ircmsg"
)

type Server struct {
	channels         ChannelNameMap
	clients          *ClientLookupSet
	commands         chan Command
	ctime            time.Time
	db               *sql.DB
	idle             chan *Client
	motdLines        []string
	name             string
	newConns         chan net.Conn
	operators        map[Name][]byte
	password         []byte
	signals          chan os.Signal
	proxyAllowedFrom []string
	whoWas           *WhoWasList
	theaters         map[Name][]byte
	isupport         *ISupportList
}

var (
	SERVER_SIGNALS = []os.Signal{syscall.SIGINT, syscall.SIGHUP,
		syscall.SIGTERM, syscall.SIGQUIT}
)

func NewServer(config *Config) *Server {
	server := &Server{
		channels:         make(ChannelNameMap),
		clients:          NewClientLookupSet(),
		commands:         make(chan Command),
		ctime:            time.Now(),
		db:               OpenDB(config.Server.Database),
		idle:             make(chan *Client),
		name:             NewName(config.Server.Name),
		newConns:         make(chan net.Conn),
		operators:        config.Operators(),
		signals:          make(chan os.Signal, len(SERVER_SIGNALS)),
		proxyAllowedFrom: config.Server.ProxyAllowedFrom,
		whoWas:           NewWhoWasList(100),
		theaters:         config.Theaters(),
	}

	// ensure that there is a minimum number of args specified for every command
	for name, _ := range parseCommandFuncs {
		_, exists := commandMinimumArgs[name]
		if !exists {
			log.Fatal("commandMinArgs not found for ", name)
		}
	}

	if config.Server.MOTD != "" {
		file, err := os.Open(config.Server.MOTD)
		if err == nil {
			defer file.Close()

			reader := bufio.NewReader(file)
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				line = strings.TrimRight(line, "\r\n")

				server.motdLines = append(server.motdLines, line)
			}
		}
	}

	if config.Server.Password != "" {
		server.password = config.Server.PasswordBytes()
	}

	server.loadChannels()

	for _, addr := range config.Server.Listen {
		server.listen(addr, config.TLSListeners())
	}

	if config.Server.Wslisten != "" {
		server.wslisten(config.Server.Wslisten, config.Server.TLSListeners)
	}

	signal.Notify(server.signals, SERVER_SIGNALS...)

	// add RPL_ISUPPORT tokens
	server.isupport = NewISupportList()
	server.isupport.Add("CASEMAPPING", "ascii")
	// server.isupport.Add("CHANMODES", "")  //TODO(dan): Channel mode list here
	// server.isupport.Add("CHANNELLEN", "") //TODO(dan): Support channel length
	server.isupport.Add("CHANTYPES", "#")
	server.isupport.Add("EXCEPTS", "")
	server.isupport.Add("INVEX", "")
	// server.isupport.Add("KICKLEN", "") //TODO(dan): Support kick length?
	// server.isupport.Add("MAXLIST", "") //TODO(dan): Support max list length?
	// server.isupport.Add("MODES", "")   //TODO(dan): Support max modes?
	server.isupport.Add("NETWORK", config.Network.Name)
	// server.isupport.Add("NICKLEN", "") //TODO(dan): Support nick length
	server.isupport.Add("PREFIX", "(qaohv)~&@%+")
	// server.isupport.Add("STATUSMSG", "@+") //TODO(dan): Autogenerate based on PREFIXes, support STATUSMSG
	// server.isupport.Add("TARGMAX", "")  //TODO(dan): Support this
	// server.isupport.Add("TOPICLEN", "") //TODO(dan): Support topic length
	server.isupport.RegenerateCachedReply()

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

		channel := NewChannel(server, NewName(name), false)
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

	numCmd, ok := cmd.(*NeedMoreParamsCommand)
	if ok {
		client.ErrNeedMoreParams(numCmd.code)
		return
	}

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
		client.Send("notice")
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

func (s *Server) listen(addr string, tlsMap map[Name]*tls.Config) {
	config, listenTLS := tlsMap[NewName(addr)]

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(s, "listen error: ", err)
	}

	tlsString := "plaintext"
	if listenTLS {
		listener = tls.NewListener(listener, config)
		tlsString = "TLS"
	}
	Log.info.Printf("%s listening on %s using %s.", s, addr, tlsString)

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

func (s *Server) wslisten(addr string, tlsMap map[string]*TLSListenConfig) {
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
		config, listenTLS := tlsMap[addr]

		tlsString := "plaintext"
		var err error
		if listenTLS {
			tlsString = "TLS"
		}
		Log.info.Printf("%s websocket listening on %s using %s.", s, addr, tlsString)

		if listenTLS {
			err = http.ListenAndServeTLS(addr, config.Cert, config.Key, nil)
		} else {
			err = http.ListenAndServe(addr, nil)
		}
		if err != nil {
			Log.error.Printf("%s listenAndServe (%s) error: %s", s, tlsString, err)
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
	c.registered = true

	c.Send("Intro to the network")
	c.Register()
	c.RplWelcome()
	c.RplYourHost()
	c.RplCreated()
	c.RplMyInfo()
	c.RplISupport()
	s.MOTD(c)
}

func (server *Server) MOTD(client *Client) {
	if len(server.motdLines) < 1 {
		c.Send("send")
		client.ErrNoMOTD()
		return
	}

	client.RplMOTDStart()
	for _, line := range server.motdLines {
		c.Send("send")
		client.RplMOTD(line)
	}
	c.Send("send")
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

// PASS <password>
func passHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if client.Registered {
		client.Send("send")
		client.ErrAlreadyRegistered()
		return false
	}

	// check the provided password
	logger.Fatal("Implement PASS command")
	password := []byte(args[0])
	if ComparePassword(server.password, password) != nil {
		logger.Fatal("SEND BACK REJECTION")
		client.Quit("bad password")
		return true
	}

	client.authorized = true
	return false
}

// PROXY TCP4/6 SOURCEIP DESTIP SOURCEPORT DESTPORT
// http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt
func proxyHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	clientAddress := IPString(client.socket.conn.RemoteAddr()).String()
	clientHostname := client.hostname.String()

	for _, address := range server.proxyAllowedFrom {
		if clientHostname == address || clientAddress == address {
			client.hostname = LookupHostname(NewName(msg.Params[1]))
			return false
		}
	}

	client.Quit("PROXY command is not usable from your address")
	return true
}

// USER <username> * 0 <realname>
func userHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if client.Registered {
		client.Send("send")
		client.ErrAlreadyRegistered()
		return false
	}

	if !client.authorized {
		client.Quit("bad password")
		return true
	}

	if client.username != "" && client.realname != "" {
		return false
	}

	// set user info and log client in
	//TODO(dan): Could there be a race condition here with adding/removing the client?
	//TODO(dan): we should do something like server.clients.Replace(client) instead

	// we do it this way to ONLY replace what hasn't already been set
	server.clients.Remove(client)

	if client.username != "" {
		client.username = msg.username
	}
	if client.realname != "" {
		client.realname = msg.realname
	}
	client.updateNickMask()

	server.clients.Add(client)

	server.tryRegister(client)
}

// QUIT [<reason>]
func quitHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	reason := "Quit"
	if len(msg.Params) > 0 {
		reason += ": " + msg.Params[0]
	}
	client.Quit(msg.message)
	return true
}

//
// normal commands
//

// PING <server1> [<server2>]
func pingHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// client.Socket.Send(response here)
	return true
}

// PONG <server> [ <server2> ]
func pongHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	//TODO(dan): update client idle timer from this
	//TODO(dan): use this to affect how often we send pings
	return true
}

// JOIN <channel>{,<channel>} [<key>{,<key>}]
// JOIN 0
func joinHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// handle JOIN 0
	if msg.Params[0] == "0" {
		for channel := range client.channels {
			channel.Part(client, client.Nick().Text())
		}
		return false
	}

	// handle regular JOINs
	channels := strings.Split(msg.Params[0], ",")
	var keys []string
	if len(msg.Params) > 1 {
		keys = strings.Split(msg.Params[1], ",")
	}

	for i, name := range channels {
		if !name.IsChannel() {
			log.Fatal("Implement ErrNoSuchChannel")
			continue
		}

		channel := s.channels.Get(name)
		if channel == nil {
			channel = NewChannel(s, name, true)
		}

		var key string
		if len(keys) > i {
			key = keys[i]
		}

		channel.Join(client, key)
	}
}

// PART <channel>{,<channel>} [<reason>]
func partHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	channels := strings.Split(msg.Params[0], ",")
	var reason string //TODO(dan): should this be the user's nickname instead of empty?
	if len(msg.Params) > 1 {
		reason = msg.Params[1]
	}

	for _, chname := range channels {
		channel := server.channels.Get(chname)

		if channel == nil {
			log.Fatal("Implement ErrNoSuchChannel")
			continue
		}

		channel.Part(client, m.Message())
	}
}

// TOPIC <channel> [<topic>]
func topicHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	channel := server.channels.Get(msg.Params[0])
	if channel == nil {
		log.Fatal("Implement ErrNoSuchChannel")
		return
	}

	if len(msg.Params) > 1 {
		channel.SetTopic(client, msg.Params[1])
	} else {
		channel.GetTopic(client)
	}
}

// PRIVMSG <target>{,<target>} <message>
func privmsgHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	targets := strings.Split(msg.Params[0], ",")
	message := msg.Params[1]

	for _, target := range targets {
		if target.IsChannel() {
			channel := server.channels.Get(target)
			if channel == nil {
				client.Send("send")
				client.ErrNoSuchChannel(target)
				continue
			}
			channel.PrivMsg(client, message)
		} else {
			user := server.clients.Get(target)
			if user == nil {
				client.Send("send")
				client.ErrNoSuchNick(target)
				return
			}
			user.Send("content here")
			if user.flags[Away] {
				client.Send("target is AWAY")
			}
		}
	}
}

func (client *Client) WhoisChannelsNames(target *Client) []string {
	isMultiPrefix := target.capabilities[MultiPrefix]
	var chstrs []string
	index := 0
	for channel := range client.channels {
		// channel is secret and the target can't see it
		if !target.flags[Operator] && channel.flags[Secret] && !channel.members.Has(target) {
			continue
		}
		chstrs = append(chstrs, channel.members[client].Prefixes(isMultiPrefix)+channel.name.String())
		index++
	}
	return chstrs
}

// WHOIS [ <target> ] <mask> *( "," <mask> )
func whoisHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var masks string
	var target string

	if len(msg.Params) > 1 {
		target = msg.Params[0]
		masks = msg.Params[1]
	} else {
		masks = msg.Params[0]
	}

	// TODO implement target query
	for _, mask := range masks {
		matches := server.clients.FindAll(mask)
		if len(matches) == 0 {
			client.ErrNoSuchNick(mask)
			client.Send("NOSUCHNICK")
			continue
		}
		for mclient := range matches {
			client.RplWhois(mclient)
			client.Send("WHOIS")
		}
	}
}

func whoChannel(client *Client, channel *Channel, friends ClientSet) {
	for member := range channel.members {
		if !client.flags[Invisible] || friends[client] {
			client.Send("send")
			client.RplWhoReply(channel, member)
		}
	}
}

// WHO [ <mask> [ "o" ] ]
func whoHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	friends := client.Friends()

	var mask string
	if len(msg.Params) > 0 {
		mask = NewName(msg.Params[0])
	}

	//TODO(dan): is this used and would I put this param in the Modern doc?
	// if not, can we remove it?
	var operatorOnly bool
	if len(msg.Params) > 1 && msr.Params[1] == "o" {
		operatorOnly = true
	}

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
			client.Send("REPLY")
		}
	}

	client.RplEndOfWho(mask)
	client.Send("ENDOFWHO")
}

// OPER <name> <password>
func operHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	name = NewName(msg.Params[0])
	hash = server.operators[name]
	password = []byte(msg.Params[1])

	err = ComparePassword(hash, password)

	if (hash == nil) || (err != nil) {
		client.ErrPasswdMismatch()
		client.Send("PASSWDBAD")
		return true
	}

	//TODO(dan): Split this into client.makeOper() ??
	client.flags[Operator] = true
	client.RplYoureOper()
	client.Send("YOUROPER")
	client.Reply(RplModeChanges(client, client, ModeChanges{&ModeChange{
		mode: Operator,
		op:   Add,
	}}))
	client.Send("OPERMODECHANGE")
}

// AWAY [<message>]
func awayHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var isAway bool
	var text string
	if len(msg.Params) > 0 {
		isAway = True
		text = NewText(msg.Params[0])
	}

	if isAway {
		client.flags[Away] = true
	} else {
		delete(client.flags, Away)
	}
	client.awayMessage = text

	var op ModeOp
	if client.flags[Away] {
		op = Add
		client.Send("imaway")
		client.RplNowAway()
	} else {
		op = Remove
		client.Send("unaway")
		client.RplUnAway()
	}
	client.Send("mode changes I guess?")
	client.Reply(RplModeChanges(client, client, ModeChanges{&ModeChange{
		mode: Away,
		op:   op,
	}}))
}

// ISON <nick>{ <nick>}
func isonHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var nicks = NewNames(msg.Params)

	ison := make([]string, 0)
	for _, nick := range nicks {
		if iclient := server.clients.Get(nick); iclient != nil {
			ison = append(ison, iclient.Nick().String())
		}
	}

	client.Send("ISON")
	client.RplIsOn(ison)
}

// MOTD [<target>]
func motdHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	//TODO(dan): hook this up when we have multiple servers I guess???
	var target string
	if len(msg.Params) > 0 {
		target = NewName(msg.Params[0])
	}

	client.Send("MOTD")
	server.MOTD(msg.Client())
}

// NOTICE <target>{,<target>} <message>
func noticeHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	targetName := NewName(msg.Params[0])
	message := NewText(msg.Params[1])

	if targetName.IsChannel() {
		channel := server.channels.Get(targetName)
		if channel == nil {
			client.Send("ERRNOSUCHCHAN")
			client.ErrNoSuchChannel(targetName)
			return
		}

		channel.Notice(client, message)
		return
	}

	target := server.clients.Get(targetName)
	if target == nil {
		client.Send("ERRNOSUCHNICK")
		client.ErrNoSuchNick(targetName)
		return
	}
	client.Send("NOTICE")
	target.Reply(RplNotice(client, target, message))
}

// KICK <channel>{,<channel>} <user>{,<user>} [<comment>]
func kickHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	channels := NewNames(strings.Split(msg.Params[0], ","))
	users := NewNames(strings.Split(msg.Params[1], ","))
	if (len(channels) != len(users)) && (len(users) != 1) {
		client.Send("NotEnoughArgs??")
		return false
		// not needed return nil, NotEnoughArgsError
	}

	kicks := make(map[Name]Name)
	for index, channel := range channels {
		if len(users) == 1 {
			kicks[channel] = users[0]
		} else {
			kicks[channel] = users[index]
		}
	}

	var comment string
	if len(msg.Params) > 2 {
		comment = msg.Params[2]
	}
	for chname, nickname := range kicks {
		channel := server.channels.Get(chname)
		if channel == nil {
			client.ErrNoSuchChannel(chname)
			client.Send("send")
			continue
		}

		target := server.clients.Get(nickname)
		if target == nil {
			client.ErrNoSuchNick(nickname)
			client.Send("send")
			continue
		}

		// make sure client has privs to kick the given user
		var hasPrivs bool
		for _, mode := range ChannelPrivModes {
			if channel.members[client][mode] {
				hasPrivs = true

				// admins cannot kick other admins
				if mode == ChannelAdmin && channel.members[target][ChannelAdmin] {
					hasPrivs = false
				}

				break
			} else if channel.members[target][mode] {
				break
			}
		}

		if hasPrivs {
			if comment == "" {
				channel.Kick(client, target, nickname)
			} else {
				channel.Kick(client, target, comment)
			}
		} else {
			client.ErrChanOPrivIsNeeded(channel)
			client.Send("send")
		}
	}
}

// LIST [<channel>{,<channel>} [<server>]]
func listHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var channels []Name
	if len(args) > 0 {
		channels = NewNames(strings.Split(args[0], ","))
	}
	var target Name
	if len(args) > 1 {
		target = NewName(args[1])
	}

	//TODO(dan): target server when we have multiple servers
	//TODO(dan): we should continue just fine if it's this current server though
	if target != "" {
		client.ErrNoSuchServer(msg.target)
		client.Send("send")
		return
	}

	if len(channels) == 0 {
		for _, channel := range server.channels {
			if !client.flags[Operator] && channel.flags[Secret] {
				continue
			}
			client.RplList(channel)
			client.Send("send")
		}
	} else {
		for _, chname := range channels {
			channel := server.channels.Get(chname)
			if channel == nil || (!client.flags[Operator] && channel.flags[Secret]) {
				client.ErrNoSuchChannel(chname)
				client.Send("send")
				continue
			}
			client.RplList(channel)
			client.Send("send")
		}
	}
	client.RplListEnd(server)
	client.Send("send")
}

// NAMES [<channel>{,<channel>}]
func namesHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var channels []Name
	if len(args) > 0 {
		channels = NewNames(strings.Split(args[0], ","))
	}
	var target Name
	if len(args) > 1 {
		target = NewName(args[1])
	}

	if len(channels) == 0 {
		for _, channel := range server.channels {
			channel.Names(client)
		}
		return false
	}

	for _, chname := range channels {
		channel := server.channels.Get(chname)
		if channel == nil {
			client.ErrNoSuchChannel(chname)
			client.Send("send")
			continue
		}
		channel.Names(client)
		client.Send("send")
	}
}

// VERSION [<server>]
func versionHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var target Name
	if len(args) > 0 {
		target = NewName(args[0])
	}
	if (target != "") && (target != server.name) {
		client.ErrNoSuchServer(target)
		client.Send("send")
		return
	}

	client.RplVersion()
	client.Send("send")
	client.RplISupport()
	client.Send("send")
}

// INVITE <nickname> <channel>
func inviteHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	nickname := NewName(msg.Params[0])
	channelName := NewName(msg.Params[1])

	target := server.clients.Get(nickname)
	if target == nil {
		client.ErrNoSuchNick(nickname)
		client.Send("send")
		return
	}

	channel := server.channels.Get(channelName)
	if channel == nil {
		client.RplInviting(target, channelName)
		client.Send("send")
		target.Reply(RplInviteMsg(client, target, channelName))
		client.Send("send")
		return
	}

	channel.Invite(target, client)
}

// TIME [<server>]
func timeHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var target Name
	if len(msg.Params) > 0 {
		target = NewName(msg.Params[0])
	}
	if (target != "") && (target != server.name) {
		client.ErrNoSuchServer(target)
		client.Send("send")
		return
	}
	client.RplTime()
	client.Send("send")
}

// KILL <nickname> <comment>
func killHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	nickname := NewName(msg.Params[0])
	comment := NewText(msg.Params[1])

	if !client.flags[Operator] {
		client.ErrNoPrivileges()
		client.Send("send")
		return
	}

	target := server.clients.Get(nickname)
	if target == nil {
		client.ErrNoSuchNick(nickname)
		client.Send("send")
		return
	}

	//TODO(dan): make below format match that from other IRCds
	quitMsg := fmt.Sprintf("KILLed by %s: %s", client.Nick(), comment)
	target.Quit(NewText(quitMsg))
	return true
}

// WHOWAS <nickname> [<count> [<server>]]
func whowasHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	nicknames := NewNames(strings.Split(msg.Params[0], ","))

	var count int
	if len(msg.Params) > 1 {
		count, _ = strconv.ParseInt(msg.Params[1], 10, 64)
	}
	var target Name
	if len(msg.Params) > 2 {
		target = NewName(msg.Params[2])
	}
	for _, nickname := range nicknames {
		results := server.whoWas.Find(nickname, msg.count)
		if len(results) == 0 {
			client.ErrWasNoSuchNick(nickname)
			client.Send("send")
		} else {
			for _, whoWas := range results {
				client.RplWhoWasUser(whoWas)
				client.Send("send")
			}
		}
		client.Send(nil, server.Name, RPL_ENDOFWHOWAS, nickname, "End of WHOWAS")
	}
}
