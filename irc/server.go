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
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/DanielOaks/girc-go/ircmsg"
	"github.com/tidwall/buntdb"
)

type Server struct {
	accounts            map[string]Account
	channels            ChannelNameMap
	clients             *ClientLookupSet
	commands            chan Command
	ctime               time.Time
	db                  *sql.DB
	store               buntdb.DB
	idle                chan *Client
	motdLines           []string
	name                Name
	nameString          string // cache for server name string since it's used with almost every reply
	newConns            chan clientConn
	operators           map[Name][]byte
	password            []byte
	accountRegistration *AccountRegistration
	signals             chan os.Signal
	proxyAllowedFrom    []string
	whoWas              *WhoWasList
	theaters            map[Name][]byte
	isupport            *ISupportList
	checkIdent          bool
}

var (
	SERVER_SIGNALS = []os.Signal{
		syscall.SIGINT,
		syscall.SIGHUP, // eventually we expect to use HUP to reload config
		syscall.SIGTERM,
		syscall.SIGQUIT,
	}
)

type clientConn struct {
	Conn  net.Conn
	IsTLS bool
}

func NewServer(config *Config) *Server {
	server := &Server{
		accounts:         make(map[string]Account),
		channels:         make(ChannelNameMap),
		clients:          NewClientLookupSet(),
		commands:         make(chan Command),
		ctime:            time.Now(),
		db:               OpenDB(config.Datastore.SQLitePath),
		idle:             make(chan *Client),
		name:             NewName(config.Server.Name),
		nameString:       NewName(config.Server.Name).String(),
		newConns:         make(chan clientConn),
		operators:        config.Operators(),
		signals:          make(chan os.Signal, len(SERVER_SIGNALS)),
		proxyAllowedFrom: config.Server.ProxyAllowedFrom,
		whoWas:           NewWhoWasList(config.Limits.WhowasEntries),
		theaters:         config.Theaters(),
		checkIdent:       config.Server.CheckIdent,
	}

	// open data store
	db, err := buntdb.Open(config.Datastore.Path)
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to open datastore: %s", err.Error()))
	}
	defer db.Close()
	server.store = *db

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
				// "- " is the required prefix for MOTD, we just add it here to make
				// bursting it out to clients easier
				line = fmt.Sprintf("- %s", line)

				server.motdLines = append(server.motdLines, line)
			}
		}
	}

	//TODO(dan): Hot damn this is an ugly hack. Fix it properly at some point.
	ChannelNameExpr = regexp.MustCompile(fmt.Sprintf(`^[#][\pL\pN\pP\pS]{1,%d}$`, config.Limits.ChannelLen))
	NicknameExpr = regexp.MustCompile(fmt.Sprintf("^[\\pL\\pN\\pP\\pS]{1,%d}$", config.Limits.NickLen))

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

	// registration
	accountReg := NewAccountRegistration(config.Registration.Accounts)
	server.accountRegistration = &accountReg

	// Attempt to clean up when receiving these signals.
	signal.Notify(server.signals, SERVER_SIGNALS...)

	// add RPL_ISUPPORT tokens
	server.isupport = NewISupportList()
	server.isupport.Add("CASEMAPPING", "ascii")
	// server.isupport.Add("CHANMODES", "")  //TODO(dan): Channel mode list here
	server.isupport.Add("CHANNELLEN", strconv.Itoa(config.Limits.ChannelLen))
	server.isupport.Add("CHANTYPES", "#")
	server.isupport.Add("EXCEPTS", "")
	server.isupport.Add("INVEX", "")
	// server.isupport.Add("KICKLEN", "") //TODO(dan): Support kick length?
	// server.isupport.Add("MAXLIST", "") //TODO(dan): Support max list length?
	// server.isupport.Add("MODES", "")   //TODO(dan): Support max modes?
	server.isupport.Add("NETWORK", config.Network.Name)
	server.isupport.Add("NICKLEN", strconv.Itoa(config.Limits.NickLen))
	server.isupport.Add("PREFIX", "(qaohv)~&@%+")
	// server.isupport.Add("STATUSMSG", "@+") //TODO(dan): Support STATUSMSG
	// server.isupport.Add("TARGMAX", "")  //TODO(dan): Support this
	// server.isupport.Add("TOPICLEN", "") //TODO(dan): Support topic length

	// account registration
	if server.accountRegistration.Enabled {
		// 'none' isn't shown in the REGCALLBACKS vars
		var enabledCallbacks []string
		for _, name := range server.accountRegistration.EnabledCallbacks {
			if name != "*" {
				enabledCallbacks = append(enabledCallbacks, name)
			}
		}

		server.isupport.Add("REGCOMMANDS", "CREATE,VERIFY")
		server.isupport.Add("REGCALLBACKS", strings.Join(enabledCallbacks, ","))
		server.isupport.Add("REGCREDTYPES", "passphrase,certfp")
	}

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
		channel.key = key
		channel.topic = topic
		channel.userLimit = userLimit
		loadChannelList(channel, banList, BanMask)
		loadChannelList(channel, exceptList, ExceptMask)
		loadChannelList(channel, inviteList, InviteMask)
	}
}

func (server *Server) Shutdown() {
	server.db.Close()
	for _, client := range server.clients.byNick {
		client.Notice("Server is shutting down")
	}

	if err := server.db.Close(); err != nil {
		Log.error.Println("Server.Shutdown: error:", err)
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
			NewClient(server, conn.Conn, conn.IsTLS)

		/*TODO(dan): LOOK AT THIS MORE CLOSELY
		case cmd := <-server.commands:
			server.processCommand(cmd)
		*/

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
		config.ClientAuth = tls.RequestClientCert
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

			newConn := clientConn{
				Conn:  conn,
				IsTLS: listenTLS,
			}

			s.newConns <- newConn
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

		newConn := clientConn{
			Conn:  WSContainer{ws},
			IsTLS: false, //TODO(dan): track TLS or not here properly
		}
		s.newConns <- newConn
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
	c.Register()

	// send welcome text
	//NOTE(dan): we specifically use the NICK here instead of the nickmask
	// see http://modern.ircdocs.horse/#rplwelcome-001 for details on why we avoid using the nickmask
	c.Send(nil, s.nameString, RPL_WELCOME, c.nickString, fmt.Sprintf("Welcome to the Internet Relay Network %s", c.nickString))
	c.Send(nil, s.nameString, RPL_YOURHOST, c.nickString, fmt.Sprintf("Your host is %s, running version %s", s.nameString, VER))
	c.Send(nil, s.nameString, RPL_CREATED, c.nickString, fmt.Sprintf("This server was created %s", s.ctime.Format(time.RFC1123)))
	//TODO(dan): Look at adding last optional [<channel modes with a parameter>] parameter
	c.Send(nil, s.nameString, RPL_MYINFO, c.nickString, s.nameString, VER, supportedUserModesString, supportedChannelModesString)
	c.RplISupport()
	s.MOTD(c)
	c.Send(nil, c.nickMaskString, RPL_UMODEIS, c.nickString, c.ModeString())
}

func (server *Server) MOTD(client *Client) {
	if len(server.motdLines) < 1 {
		client.Send(nil, server.nameString, ERR_NOMOTD, client.nickString, "MOTD File is missing")
		return
	}

	client.Send(nil, server.nameString, RPL_MOTDSTART, client.nickString, fmt.Sprintf("- %s Message of the day - ", server.nameString))
	for _, line := range server.motdLines {
		client.Send(nil, server.nameString, RPL_MOTD, client.nickString, line)
	}
	client.Send(nil, server.nameString, RPL_ENDOFMOTD, client.nickString, "End of MOTD command")
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
	if client.registered {
		client.Send(nil, server.nameString, ERR_ALREADYREGISTRED, client.nickString, "You may not reregister")
		return false
	}

	// if no password exists, skip checking
	if len(server.password) == 0 {
		client.authorized = true
		return false
	}

	// check the provided password
	password := []byte(msg.Params[0])
	if ComparePassword(server.password, password) != nil {
		client.Send(nil, server.nameString, ERR_PASSWDMISMATCH, client.nickString, "Password incorrect")
		client.Send(nil, server.nameString, "ERROR", "Password incorrect")
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
	if client.registered {
		client.Send(nil, server.nameString, ERR_ALREADYREGISTRED, client.nickString, "You may not reregister")
		return false
	}

	if !client.authorized {
		client.Quit("Bad password")
		return true
	}

	if client.username != "" && client.realname != "" {
		return false
	}

	// confirm that username is valid
	//
	if !Name(msg.Params[0]).IsNickname() {
		client.Send(nil, "", "ERROR", "Malformed username")
		return true
	}

	// set user info and log client in
	//TODO(dan): Could there be a race condition here with adding/removing the client?
	//TODO(dan): we should do something like server.clients.Replace(client) instead

	// we do it this way to ONLY replace what hasn't already been set
	server.clients.Remove(client)

	if !client.HasUsername() {
		client.username = Name("~" + msg.Params[0])
		client.updateNickMask()
	}
	if client.realname == "" {
		client.realname = msg.Params[3]
	}

	server.clients.Add(client)
	server.tryRegister(client)

	return false
}

// QUIT [<reason>]
func quitHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	reason := "Quit"
	if len(msg.Params) > 0 {
		reason += ": " + msg.Params[0]
	}
	client.Quit(reason)
	return true
}

//
// normal commands
//

// PING <server1> [<server2>]
func pingHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	client.Send(nil, server.nameString, "PONG", msg.Params...)
	return false
}

// PONG <server> [ <server2> ]
func pongHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// client gets touched when they send this command, so we don't need to do anything
	return false
}

// JOIN <channel>{,<channel>} [<key>{,<key>}]
// JOIN 0
func joinHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// handle JOIN 0
	if msg.Params[0] == "0" {
		for channel := range client.channels {
			channel.Part(client, client.nickString)
		}
		return false
	}

	// handle regular JOINs
	channels := strings.Split(msg.Params[0], ",")
	var keys []string
	if len(msg.Params) > 1 {
		keys = strings.Split(msg.Params[1], ",")
	}

	var name Name
	for i, nameString := range channels {
		name = Name(nameString)
		if !name.IsChannel() {
			fmt.Println("ISN'T CHANNEL NAME:", nameString)
			client.Send(nil, server.nameString, ERR_NOSUCHCHANNEL, client.nickString, nameString, "No such channel")
			continue
		}

		channel := server.channels.Get(name)
		if channel == nil {
			channel = NewChannel(server, name, true)
		}

		var key string
		if len(keys) > i {
			key = keys[i]
		}

		channel.Join(client, key)
	}
	return false
}

// PART <channel>{,<channel>} [<reason>]
func partHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	channels := strings.Split(msg.Params[0], ",")
	var reason string //TODO(dan): if this isn't supplied here, make sure the param doesn't exist in the PART message sent to other users
	if len(msg.Params) > 1 {
		reason = msg.Params[1]
	}

	for _, chname := range channels {
		channel := server.channels.Get(Name(chname))

		if channel == nil {
			client.Send(nil, server.nameString, ERR_NOSUCHCHANNEL, client.nickString, chname, "No such channel")
			continue
		}

		channel.Part(client, reason)
	}
	return false
}

// TOPIC <channel> [<topic>]
func topicHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	channel := server.channels.Get(Name(msg.Params[0]))
	if channel == nil {
		client.Send(nil, server.nameString, ERR_NOSUCHCHANNEL, client.nickString, msg.Params[0], "No such channel")
		return false
	}

	if len(msg.Params) > 1 {
		channel.SetTopic(client, msg.Params[1])
	} else {
		channel.GetTopic(client)
	}
	return false
}

// PRIVMSG <target>{,<target>} <message>
func privmsgHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	targets := strings.Split(msg.Params[0], ",")
	message := msg.Params[1]

	var target Name
	for _, targetString := range targets {
		target = Name(targetString)
		if target.IsChannel() {
			channel := server.channels.Get(target)
			if channel == nil {
				client.Send(nil, server.nameString, ERR_NOSUCHCHANNEL, client.nickString, targetString, "No such channel")
				continue
			}
			channel.PrivMsg(client, message)
		} else {
			user := server.clients.Get(target)
			if user == nil {
				client.Send(nil, server.nameString, ERR_NOSUCHNICK, targetString, "No such nick")
				continue
			}
			user.Send(nil, client.nickMaskString, "PRIVMSG", user.nickString, message)
			if user.flags[Away] {
				//TODO(dan): possibly implement cooldown of away notifications to users
				client.Send(nil, server.nameString, RPL_AWAY, user.nickString, user.awayMessage)
			}
		}
	}
	return false
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
	var masksString string
	//var target string

	if len(msg.Params) > 1 {
		//target = msg.Params[0]
		masksString = msg.Params[1]
	} else {
		masksString = msg.Params[0]
	}

	if client.flags[Operator] {
		masks := strings.Split(masksString, ",")
		for _, mask := range masks {
			matches := server.clients.FindAll(Name(mask))
			if len(matches) == 0 {
				client.Send(nil, client.server.nameString, ERR_NOSUCHNICK, mask, "No such nick")
				continue
			}
			for mclient := range matches {
				mclient.getWhoisOf(client)
			}
		}
	} else {
		// specifically treat this as a single lookup rather than splitting as we do above
		// this is by design
		mclient := server.clients.Get(Name(masksString))
		if mclient == nil {
			client.Send(nil, client.server.nameString, ERR_NOSUCHNICK, masksString, "No such nick")
			// fall through, ENDOFWHOIS is always sent
		} else {
			client.getWhoisOf(mclient)
		}
	}
	client.Send(nil, server.nameString, RPL_ENDOFWHOIS, client.nickString, masksString, "End of /WHOIS list")
	return false
}

func (client *Client) getWhoisOf(target *Client) {
	client.Send(nil, client.server.nameString, RPL_WHOISUSER, client.nickString, target.nickString, target.username.String(), target.hostname.String(), "*", target.realname)
	if target.flags[Operator] {
		client.Send(nil, client.server.nameString, RPL_WHOISOPERATOR, client.nickString, target.nickString, "is an IRC operator")
	}
	client.Send(nil, client.server.nameString, RPL_WHOISIDLE, client.nickString, target.nickString, string(target.IdleSeconds()), string(target.SignonTime()), "seconds idle, signon time")
	for _, line := range client.WhoisChannelsNames(target) {
		client.Send(nil, client.server.nameString, RPL_WHOISCHANNELS, client.nickString, target.nickString, line)
	}
}

// <channel> <user> <host> <server> <nick> ( "H" / "G" ) ["*"] [ ( "@" / "+" ) ]
// :<hopcount> <real name>
func (target *Client) RplWhoReply(channel *Channel, client *Client) {
	channelName := "*"
	flags := ""

	if client.flags[Away] {
		flags = "G"
	} else {
		flags = "H"
	}
	if client.flags[Operator] {
		flags += "*"
	}

	if channel != nil {
		flags += channel.members[client].Prefixes(target.capabilities[MultiPrefix])
		channelName = channel.name.String()
	}
	target.Send(nil, target.server.nameString, RPL_WHOREPLY, target.nickString, channelName, client.username.String(), client.hostname.String(), client.server.nameString, client.nickString, flags, string(client.hops), client.realname)
}

func whoChannel(client *Client, channel *Channel, friends ClientSet) {
	for member := range channel.members {
		if !client.flags[Invisible] || friends[client] {
			client.RplWhoReply(channel, member)
		}
	}
}

// WHO [ <mask> [ "o" ] ]
func whoHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	friends := client.Friends()

	var mask Name
	if len(msg.Params) > 0 {
		mask = Name(msg.Params[0])
	}

	//TODO(dan): is this used and would I put this param in the Modern doc?
	// if not, can we remove it?
	//var operatorOnly bool
	//if len(msg.Params) > 1 && msg.Params[1] == "o" {
	//	operatorOnly = true
	//}

	if mask == "" {
		for _, channel := range server.channels {
			whoChannel(client, channel, friends)
		}
	} else if mask.IsChannel() {
		// TODO implement wildcard matching
		//TODO(dan): ^ only for opers
		channel := server.channels.Get(mask)
		if channel != nil {
			whoChannel(client, channel, friends)
		}
	} else {
		for mclient := range server.clients.FindAll(mask) {
			client.RplWhoReply(nil, mclient)
		}
	}

	client.Send(nil, server.nameString, RPL_ENDOFWHO, client.nickString, mask.String(), "End of WHO list")
	return false
}

// OPER <name> <password>
func operHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	name := NewName(msg.Params[0])
	hash := server.operators[name]
	password := []byte(msg.Params[1])

	err := ComparePassword(hash, password)

	if (hash == nil) || (err != nil) {
		client.Send(nil, server.nameString, ERR_PASSWDMISMATCH, client.nickString, "Password incorrect")
		return true
	}

	client.flags[Operator] = true
	client.Send(nil, server.nameString, RPL_YOUREOPER, client.nickString, "You are now an IRC operator")
	//TODO(dan): Should this be sent automagically as part of setting the flag/mode?
	modech := ModeChanges{&ModeChange{
		mode: Operator,
		op:   Add,
	}}
	client.Send(nil, server.nameString, "MODE", client.nickString, modech.String())
	return false
}

// AWAY [<message>]
func awayHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var isAway bool
	var text string
	if len(msg.Params) > 0 {
		isAway = true
		text = msg.Params[0]
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
		client.Send(nil, server.nameString, RPL_NOWAWAY, client.nickString, "You have been marked as being away")
	} else {
		op = Remove
		client.Send(nil, server.nameString, RPL_UNAWAY, client.nickString, "You are no longer marked as being away")
	}
	//TODO(dan): Should this be sent automagically as part of setting the flag/mode?
	modech := ModeChanges{&ModeChange{
		mode: Away,
		op:   op,
	}}
	client.Send(nil, server.nameString, "MODE", client.nickString, client.nickString, modech.String())
	return false
}

// ISON <nick>{ <nick>}
func isonHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var nicks = msg.Params

	ison := make([]string, 0)
	for _, nick := range nicks {
		if iclient := server.clients.Get(Name(nick)); iclient != nil {
			ison = append(ison, iclient.Nick().String())
		}
	}

	client.Send(nil, server.nameString, RPL_ISON, client.nickString, strings.Join(nicks, " "))
	return false
}

// MOTD [<target>]
func motdHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	//TODO(dan): hook this up when we have multiple servers I guess???
	//var target string
	//if len(msg.Params) > 0 {
	//	target = msg.Params[0]
	//}

	server.MOTD(client)
	return false
}

// NOTICE <target>{,<target>} <message>
func noticeHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	targets := strings.Split(msg.Params[0], ",")
	message := msg.Params[1]

	var target Name
	for _, targetString := range targets {
		target = Name(targetString)
		if target.IsChannel() {
			channel := server.channels.Get(target)
			if channel == nil {
				// errors silently ignored with NOTICE as per RFC
				continue
			}
			channel.PrivMsg(client, message)
		} else {
			user := server.clients.Get(target)
			if user == nil {
				// errors silently ignored with NOTICE as per RFC
				continue
			}
			user.Send(nil, client.nickMaskString, "NOTICE", user.nickString, message)
		}
	}
	return false
}

// KICK <channel>{,<channel>} <user>{,<user>} [<comment>]
func kickHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	channels := strings.Split(msg.Params[0], ",")
	users := strings.Split(msg.Params[1], ",")
	if (len(channels) != len(users)) && (len(users) != 1) {
		client.Send(nil, server.nameString, ERR_NEEDMOREPARAMS, client.nickString, "KICK", "Not enough parameters")
		return false
	}

	kicks := make(map[string]string)
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
		channel := server.channels.Get(Name(chname))
		if channel == nil {
			client.Send(nil, server.nameString, ERR_NOSUCHCHANNEL, client.nickString, chname, "No such channel")
			continue
		}

		target := server.clients.Get(Name(nickname))
		if target == nil {
			client.Send(nil, server.nameString, ERR_NOSUCHNICK, nickname, "No such nick")
			continue
		}

		// make sure client has privs to kick the given user
		//TODO(dan): split this into a separate function that checks if users have privs
		// over other users, useful for things like -aoh as well
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
				comment = nickname
			}
			channel.Kick(client, target, comment)
		} else {
			client.Send(nil, client.server.nameString, ERR_CHANOPRIVSNEEDED, chname, "You're not a channel operator")
		}
	}
	return false
}

// LIST [<channel>{,<channel>} [<server>]]
func listHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var channels []string
	if len(msg.Params) > 0 {
		channels = strings.Split(msg.Params[0], ",")
	}
	var target string
	if len(msg.Params) > 1 {
		target = msg.Params[1]
	}

	//TODO(dan): target server when we have multiple servers
	//TODO(dan): we should continue just fine if it's this current server though
	if target != "" {
		client.Send(nil, server.nameString, ERR_NOSUCHSERVER, client.nickString, target, "No such server")
		return false
	}

	if len(channels) == 0 {
		for _, channel := range server.channels {
			if !client.flags[Operator] && channel.flags[Secret] {
				continue
			}
			client.RplList(channel)
		}
	} else {
		for _, chname := range channels {
			channel := server.channels.Get(Name(chname))
			if channel == nil || (!client.flags[Operator] && channel.flags[Secret]) {
				client.Send(nil, server.nameString, ERR_NOSUCHCHANNEL, client.nickString, chname, "No such channel")
				continue
			}
			client.RplList(channel)
		}
	}
	client.Send(nil, server.nameString, RPL_LISTEND, client.nickString, "End of LIST")
	return false
}

func (target *Client) RplList(channel *Channel) {
	// get the correct number of channel members
	var memberCount int
	if target.flags[Operator] || channel.members.Has(target) {
		memberCount = len(channel.members)
	} else {
		for member := range channel.members {
			if !member.flags[Invisible] {
				memberCount += 1
			}
		}
	}

	target.Send(nil, target.server.nameString, RPL_LIST, target.nickString, channel.nameString, string(memberCount), channel.topic)
}

// NAMES [<channel>{,<channel>}]
func namesHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var channels []string
	if len(msg.Params) > 0 {
		channels = strings.Split(msg.Params[0], ",")
	}
	//var target string
	//if len(msg.Params) > 1 {
	//	target = msg.Params[1]
	//}

	if len(channels) == 0 {
		for _, channel := range server.channels {
			channel.Names(client)
		}
		return false
	}

	for _, chname := range channels {
		channel := server.channels.Get(Name(chname))
		if channel == nil {
			client.Send(nil, server.nameString, ERR_NOSUCHCHANNEL, client.nickString, chname, "No such channel")
			continue
		}
		channel.Names(client)
	}
	return false
}

// VERSION [<server>]
func versionHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var target string
	if len(msg.Params) > 0 {
		target = msg.Params[0]
	}
	if (target != "") && (Name(target) != server.name) {
		client.Send(nil, server.nameString, ERR_NOSUCHSERVER, client.nickString, target, "No such server")
		return false
	}

	client.Send(nil, server.nameString, RPL_VERSION, client.nickString, VER, server.nameString)
	client.RplISupport()
	return false
}

// INVITE <nickname> <channel>
func inviteHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	nickname := msg.Params[0]
	channelName := msg.Params[1]

	target := server.clients.Get(Name(nickname))
	if target == nil {
		client.Send(nil, server.nameString, ERR_NOSUCHNICK, client.nickString, nickname, "No such nick")
		return false
	}

	channel := server.channels.Get(Name(channelName))
	if channel == nil {
		client.Send(nil, server.nameString, RPL_INVITING, client.nickString, target.nickString, channelName)
		target.Send(nil, client.nickMaskString, "INVITE", target.nickString, channel.nameString)
		return true
	}

	channel.Invite(target, client)
	return false
}

// TIME [<server>]
func timeHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var target string
	if len(msg.Params) > 0 {
		target = msg.Params[0]
	}
	if (target != "") && (Name(target) != server.name) {
		client.Send(nil, server.nameString, ERR_NOSUCHSERVER, client.nickString, target, "No such server")
		return false
	}
	client.Send(nil, server.nameString, RPL_TIME, client.nickString, server.nameString, time.Now().Format(time.RFC1123))
	return false
}

// KILL <nickname> <comment>
func killHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	nickname := msg.Params[0]
	comment := msg.Params[1]

	target := server.clients.Get(Name(nickname))
	if target == nil {
		client.Send(nil, client.server.nameString, ERR_NOSUCHNICK, nickname, "No such nick")
		return false
	}

	quitMsg := fmt.Sprintf("Killed (%s (%s))", client.nickString, comment)
	target.Quit(quitMsg)
	target.destroy()
	return false
}

// WHOWAS <nickname> [<count> [<server>]]
func whowasHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	nicknames := strings.Split(msg.Params[0], ",")

	var count int64
	if len(msg.Params) > 1 {
		count, _ = strconv.ParseInt(msg.Params[1], 10, 64)
	}
	//var target string
	//if len(msg.Params) > 2 {
	//	target = msg.Params[2]
	//}
	for _, nickname := range nicknames {
		results := server.whoWas.Find(Name(nickname), count)
		if len(results) == 0 {
			client.Send(nil, server.nameString, ERR_WASNOSUCHNICK, client.nickString, nickname, "There was no such nickname")
		} else {
			for _, whoWas := range results {
				client.Send(nil, server.nameString, RPL_WHOWASUSER, client.nickString, whoWas.nickname.String(), whoWas.username.String(), whoWas.hostname.String(), "*", whoWas.realname)
			}
		}
		client.Send(nil, server.nameString, RPL_ENDOFWHOWAS, client.nickString, nickname, "End of WHOWAS")
	}
	return false
}
