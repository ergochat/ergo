// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
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
	"github.com/tidwall/buntdb"
)

// Limits holds the maximum limits for various things such as topic lengths
type Limits struct {
	AwayLen        int
	ChannelLen     int
	KickLen        int
	MonitorEntries int
	NickLen        int
	TopicLen       int
}

type Server struct {
	accounts            map[string]*ClientAccount
	channels            ChannelNameMap
	clients             *ClientLookupSet
	commands            chan Command
	configFilename      string
	ctime               time.Time
	store               buntdb.DB
	idle                chan *Client
	limits              Limits
	monitoring          map[string][]Client
	motdLines           []string
	name                string
	nameCasefolded      string
	networkName         string
	newConns            chan clientConn
	operators           map[string][]byte
	password            []byte
	passwords           *PasswordManager
	accountRegistration *AccountRegistration
	signals             chan os.Signal
	whoWas              *WhoWasList
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

// NewServer returns a new Oragono server.
func NewServer(configFilename string, config *Config) *Server {
	casefoldedName, err := Casefold(config.Server.Name)
	if err != nil {
		log.Println(fmt.Sprintf("Server name isn't valid: [%s]", config.Server.Name), err.Error())
		return nil
	}

	server := &Server{
		accounts:       make(map[string]*ClientAccount),
		channels:       make(ChannelNameMap),
		clients:        NewClientLookupSet(),
		commands:       make(chan Command),
		configFilename: configFilename,
		ctime:          time.Now(),
		idle:           make(chan *Client),
		limits: Limits{
			AwayLen:        int(config.Limits.AwayLen),
			ChannelLen:     int(config.Limits.ChannelLen),
			KickLen:        int(config.Limits.KickLen),
			MonitorEntries: int(config.Limits.MonitorEntries),
			NickLen:        int(config.Limits.NickLen),
			TopicLen:       int(config.Limits.TopicLen),
		},
		monitoring:     make(map[string][]Client),
		name:           config.Server.Name,
		nameCasefolded: casefoldedName,
		networkName:    config.Network.Name,
		newConns:       make(chan clientConn),
		operators:      config.Operators(),
		signals:        make(chan os.Signal, len(SERVER_SIGNALS)),
		whoWas:         NewWhoWasList(config.Limits.WhowasEntries),
		checkIdent:     config.Server.CheckIdent,
	}

	// open data store
	db, err := buntdb.Open(config.Datastore.Path)
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to open datastore: %s", err.Error()))
	}
	server.store = *db

	// load password manager
	err = server.store.View(func(tx *buntdb.Tx) error {
		saltString, err := tx.Get(keySalt)
		if err != nil {
			return fmt.Errorf("Could not retrieve salt string: %s", err.Error())
		}

		salt, err := base64.StdEncoding.DecodeString(saltString)
		if err != nil {
			return err
		}

		pwm := NewPasswordManager(salt)
		server.passwords = &pwm
		return nil
	})
	if err != nil {
		log.Fatal(fmt.Sprintf("Could not load salt: %s", err.Error()))
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
				// "- " is the required prefix for MOTD, we just add it here to make
				// bursting it out to clients easier
				line = fmt.Sprintf("- %s", line)

				server.motdLines = append(server.motdLines, line)
			}
		}
	}

	if config.Server.Password != "" {
		server.password = config.Server.PasswordBytes()
	}

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

	server.setISupport()

	return server
}

// setISupport sets up our RPL_ISUPPORT reply.
func (server *Server) setISupport() {
	// add RPL_ISUPPORT tokens
	server.isupport = NewISupportList()
	server.isupport.Add("AWAYLEN", strconv.Itoa(server.limits.AwayLen))
	server.isupport.Add("CASEMAPPING", "rfc7700")
	server.isupport.Add("CHANMODES", strings.Join([]string{ChannelModes{BanMask, ExceptMask, InviteMask}.String(), "", ChannelModes{UserLimit, Key}.String(), ChannelModes{InviteOnly, Moderated, NoOutside, OpOnlyTopic, Secret}.String()}, ","))
	server.isupport.Add("CHANNELLEN", strconv.Itoa(server.limits.ChannelLen))
	server.isupport.Add("CHANTYPES", "#")
	server.isupport.Add("EXCEPTS", "")
	server.isupport.Add("INVEX", "")
	server.isupport.Add("KICKLEN", strconv.Itoa(server.limits.KickLen))
	// server.isupport.Add("MAXLIST", "") //TODO(dan): Support max list length?
	// server.isupport.Add("MODES", "")   //TODO(dan): Support max modes?
	server.isupport.Add("MONITOR", strconv.Itoa(server.limits.MonitorEntries))
	server.isupport.Add("NETWORK", server.networkName)
	server.isupport.Add("NICKLEN", strconv.Itoa(server.limits.NickLen))
	server.isupport.Add("PREFIX", "(qaohv)~&@%+")
	// server.isupport.Add("STATUSMSG", "@+") //TODO(dan): Support STATUSMSG
	// server.isupport.Add("TARGMAX", "")  //TODO(dan): Support this
	server.isupport.Add("TOPICLEN", strconv.Itoa(server.limits.TopicLen))

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
}

func loadChannelList(channel *Channel, list string, maskMode ChannelMode) {
	if list == "" {
		return
	}
	channel.lists[maskMode].AddAll(strings.Split(list, " "))
}

func (server *Server) Shutdown() {
	//TODO(dan): Make sure we disallow new nicks
	for _, client := range server.clients.ByNick {
		client.Notice("Server is shutting down")
	}

	if err := server.store.Close(); err != nil {
		Log.error.Println("Server.Shutdown store.Close: error:", err)
	}
}

func (server *Server) Run() {
	// defer closing db/store
	defer server.store.Close()

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

func (s *Server) listen(addr string, tlsMap map[string]*tls.Config) {
	//TODO(dan): we could casemap this but... eh
	config, listenTLS := tlsMap[addr]

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
	Log.info.Printf("%s listening on %s using %s.", s.name, addr, tlsString)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				Log.error.Printf("%s accept error: %s", s.name, err)
				continue
			}
			Log.debug.Printf("%s accept: %s", s.name, conn.RemoteAddr())

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
			Log.error.Printf("%s method not allowed", s.name)
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
			Log.error.Printf("%s websocket upgrade error: %s", s.name, err)
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
		Log.info.Printf("%s websocket listening on %s using %s.", s.name, addr, tlsString)

		if listenTLS {
			err = http.ListenAndServeTLS(addr, config.Cert, config.Key, nil)
		} else {
			err = http.ListenAndServe(addr, nil)
		}
		if err != nil {
			Log.error.Printf("%s listenAndServe (%s) error: %s", s.name, tlsString, err)
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
	c.Send(nil, s.name, RPL_WELCOME, c.nick, fmt.Sprintf("Welcome to the Internet Relay Network %s", c.nick))
	c.Send(nil, s.name, RPL_YOURHOST, c.nick, fmt.Sprintf("Your host is %s, running version %s", s.name, Ver))
	c.Send(nil, s.name, RPL_CREATED, c.nick, fmt.Sprintf("This server was created %s", s.ctime.Format(time.RFC1123)))
	//TODO(dan): Look at adding last optional [<channel modes with a parameter>] parameter
	c.Send(nil, s.name, RPL_MYINFO, c.nick, s.name, Ver, supportedUserModesString, supportedChannelModesString)
	c.RplISupport()
	s.MOTD(c)
	c.Send(nil, c.nickMaskString, RPL_UMODEIS, c.nick, c.ModeString())
}

func (server *Server) MOTD(client *Client) {
	if len(server.motdLines) < 1 {
		client.Send(nil, server.name, ERR_NOMOTD, client.nick, "MOTD File is missing")
		return
	}

	client.Send(nil, server.name, RPL_MOTDSTART, client.nick, fmt.Sprintf("- %s Message of the day - ", server.name))
	for _, line := range server.motdLines {
		client.Send(nil, server.name, RPL_MOTD, client.nick, line)
	}
	client.Send(nil, server.name, RPL_ENDOFMOTD, client.nick, "End of MOTD command")
}

func (s *Server) Id() string {
	return s.name
}

func (s *Server) Nick() string {
	return s.Id()
}

//
// registration commands
//

// PASS <password>
func passHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if client.registered {
		client.Send(nil, server.name, ERR_ALREADYREGISTRED, client.nick, "You may not reregister")
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
		client.Send(nil, server.name, ERR_PASSWDMISMATCH, client.nick, "Password incorrect")
		client.Send(nil, server.name, "ERROR", "Password incorrect")
		return true
	}

	client.authorized = true
	return false
}

// USER <username> * 0 <realname>
func userHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if client.registered {
		client.Send(nil, server.name, ERR_ALREADYREGISTRED, client.nick, "You may not reregister")
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
	_, err := CasefoldName(msg.Params[0])
	if err != nil {
		client.Send(nil, "", "ERROR", "Malformed username")
		return true
	}

	// set user info and log client in
	//TODO(dan): Could there be a race condition here with adding/removing the client?
	//TODO(dan): we should do something like server.clients.Replace(client) instead

	// we do it this way to ONLY replace what hasn't already been set
	server.clients.Remove(client)

	if !client.HasUsername() {
		client.username = "~" + msg.Params[0]
		// don't bother updating nickmask here, it's not valid anyway
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
	client.Send(nil, server.name, "PONG", msg.Params...)
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
			channel.Part(client, client.nickCasefolded)
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
		casefoldedName, err := CasefoldChannel(name)
		if err != nil {
			client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, name, "No such channel")
			continue
		}

		channel := server.channels.Get(casefoldedName)
		if channel == nil {
			if len(casefoldedName) > server.limits.ChannelLen {
				client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, name, "No such channel")
				continue
			}
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
		casefoldedChannelName, err := CasefoldChannel(chname)
		channel := server.channels.Get(casefoldedChannelName)

		if err != nil || channel == nil {
			client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, chname, "No such channel")
			continue
		}

		channel.Part(client, reason)
	}
	return false
}

// TOPIC <channel> [<topic>]
func topicHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	name, err := CasefoldChannel(msg.Params[0])
	channel := server.channels.Get(name)
	if err != nil || channel == nil {
		client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, msg.Params[0], "No such channel")
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
	clientOnlyTags := GetClientOnlyTags(msg.Tags)
	targets := strings.Split(msg.Params[0], ",")
	message := msg.Params[1]

	for _, targetString := range targets {
		target, err := CasefoldChannel(targetString)
		if err == nil {
			channel := server.channels.Get(target)
			if channel == nil {
				client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, targetString, "No such channel")
				continue
			}
			channel.PrivMsg(clientOnlyTags, client, message)
		} else {
			target, err = CasefoldName(targetString)
			user := server.clients.Get(target)
			if err != nil || user == nil {
				client.Send(nil, server.name, ERR_NOSUCHNICK, target, "No such nick")
				continue
			}
			if !user.capabilities[MessageTags] {
				clientOnlyTags = nil
			}
			user.SendFromClient(client, clientOnlyTags, client.nickMaskString, "PRIVMSG", user.nick, message)
			if user.flags[Away] {
				//TODO(dan): possibly implement cooldown of away notifications to users
				client.Send(nil, server.name, RPL_AWAY, user.nick, user.awayMessage)
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
		chstrs = append(chstrs, channel.members[client].Prefixes(isMultiPrefix)+channel.name)
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
			casefoldedMask, err := Casefold(mask)
			if err != nil {
				client.Send(nil, client.server.name, ERR_NOSUCHNICK, mask, "No such nick")
				continue
			}
			matches := server.clients.FindAll(casefoldedMask)
			if len(matches) == 0 {
				client.Send(nil, client.server.name, ERR_NOSUCHNICK, mask, "No such nick")
				continue
			}
			for mclient := range matches {
				client.getWhoisOf(mclient)
			}
		}
	} else {
		// specifically treat this as a single lookup rather than splitting as we do above
		// this is by design
		casefoldedMask, err := Casefold(masksString)
		mclient := server.clients.Get(casefoldedMask)
		if err != nil || mclient == nil {
			client.Send(nil, client.server.name, ERR_NOSUCHNICK, masksString, "No such nick")
			// fall through, ENDOFWHOIS is always sent
		} else {
			client.getWhoisOf(mclient)
		}
	}
	client.Send(nil, server.name, RPL_ENDOFWHOIS, client.nick, masksString, "End of /WHOIS list")
	return false
}

func (client *Client) getWhoisOf(target *Client) {
	client.Send(nil, client.server.name, RPL_WHOISUSER, client.nick, target.nick, target.username, target.hostname, "*", target.realname)
	//TODO(dan): ...one channel per reply? really?
	for _, line := range client.WhoisChannelsNames(target) {
		client.Send(nil, client.server.name, RPL_WHOISCHANNELS, client.nick, target.nick, line)
	}
	if target.flags[Operator] {
		client.Send(nil, client.server.name, RPL_WHOISOPERATOR, client.nick, target.nick, "is an IRC operator")
	}
	if target.certfp != "" && (client.flags[Operator] || client == target) {
		client.Send(nil, client.server.name, RPL_WHOISCERTFP, client.nick, target.nick, fmt.Sprintf("has client certificate fingerprint %s", target.certfp))
	}
	client.Send(nil, client.server.name, RPL_WHOISIDLE, client.nick, target.nick, strconv.FormatUint(target.IdleSeconds(), 10), strconv.FormatInt(target.SignonTime(), 10), "seconds idle, signon time")
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
		channelName = channel.name
	}
	target.Send(nil, target.server.name, RPL_WHOREPLY, target.nick, channelName, client.username, client.hostname, client.server.name, client.nick, flags, strconv.Itoa(client.hops)+" "+client.realname)
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

	var mask string
	if len(msg.Params) > 0 {
		casefoldedMask, err := Casefold(msg.Params[0])
		if err != nil {
			client.Send(nil, server.name, ERR_UNKNOWNERROR, "WHO", "Mask isn't valid")
			return false
		}
		mask = casefoldedMask
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
	} else if mask[0] == '#' {
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

	client.Send(nil, server.name, RPL_ENDOFWHO, client.nick, mask, "End of WHO list")
	return false
}

// OPER <name> <password>
func operHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	name, err := CasefoldName(msg.Params[0])
	if err != nil {
		client.Send(nil, server.name, ERR_PASSWDMISMATCH, client.nick, "Password incorrect")
		return true
	}
	hash := server.operators[name]
	password := []byte(msg.Params[1])

	err = ComparePassword(hash, password)

	if (hash == nil) || (err != nil) {
		client.Send(nil, server.name, ERR_PASSWDMISMATCH, client.nick, "Password incorrect")
		return true
	}

	client.flags[Operator] = true
	client.Send(nil, server.name, RPL_YOUREOPER, client.nick, "You are now an IRC operator")
	//TODO(dan): Should this be sent automagically as part of setting the flag/mode?
	modech := ModeChanges{&ModeChange{
		mode: Operator,
		op:   Add,
	}}
	client.Send(nil, server.name, "MODE", client.nick, modech.String())
	return false
}

// REHASH
func rehashHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	config, err := LoadConfig(server.configFilename)

	if err != nil {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, "REHASH", fmt.Sprintf("Error rehashing config file: %s", err.Error()))
		return false
	}

	//TODO(dan): burst CAP DEL for sasl

	// set server options
	server.limits = Limits{
		AwayLen:        int(config.Limits.AwayLen),
		ChannelLen:     int(config.Limits.ChannelLen),
		KickLen:        int(config.Limits.KickLen),
		MonitorEntries: int(config.Limits.MonitorEntries),
		NickLen:        int(config.Limits.NickLen),
		TopicLen:       int(config.Limits.TopicLen),
	}
	server.operators = config.Operators()
	server.checkIdent = config.Server.CheckIdent

	// registration
	accountReg := NewAccountRegistration(config.Registration.Accounts)
	server.accountRegistration = &accountReg

	// set RPL_ISUPPORT
	oldISupportList := server.isupport
	server.setISupport()
	newISupportReplies := oldISupportList.GetDifference(server.isupport)

	// push new info to all of our clients
	for _, sClient := range server.clients.ByNick {
		for _, tokenline := range newISupportReplies {
			// ugly trickery ahead
			sClient.Send(nil, client.server.name, RPL_ISUPPORT, append([]string{sClient.nick}, tokenline...)...)
		}
	}

	client.Send(nil, server.name, RPL_REHASHING, client.nick, "ircd.yaml", "Rehashing")
	return false
}

// AWAY [<message>]
func awayHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var isAway bool
	var text string
	if len(msg.Params) > 0 {
		isAway = true
		text = msg.Params[0]
		if len(text) > server.limits.AwayLen {
			text = text[:server.limits.AwayLen]
		}
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
		client.Send(nil, server.name, RPL_NOWAWAY, client.nick, "You have been marked as being away")
	} else {
		op = Remove
		client.Send(nil, server.name, RPL_UNAWAY, client.nick, "You are no longer marked as being away")
	}
	//TODO(dan): Should this be sent automagically as part of setting the flag/mode?
	modech := ModeChanges{&ModeChange{
		mode: Away,
		op:   op,
	}}
	client.Send(nil, server.name, "MODE", client.nick, client.nick, modech.String())

	// dispatch away-notify
	for friend := range client.Friends(AwayNotify) {
		if client.flags[Away] {
			friend.SendFromClient(client, nil, client.nickMaskString, "AWAY", client.awayMessage)
		} else {
			friend.SendFromClient(client, nil, client.nickMaskString, "AWAY")
		}
	}

	return false
}

// ISON <nick>{ <nick>}
func isonHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var nicks = msg.Params

	var err error
	var casefoldedNick string
	ison := make([]string, 0)
	for _, nick := range nicks {
		casefoldedNick, err = CasefoldName(nick)
		if err != nil {
			continue
		}
		if iclient := server.clients.Get(casefoldedNick); iclient != nil {
			ison = append(ison, iclient.nick)
		}
	}

	client.Send(nil, server.name, RPL_ISON, client.nick, strings.Join(nicks, " "))
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
	clientOnlyTags := GetClientOnlyTags(msg.Tags)
	targets := strings.Split(msg.Params[0], ",")
	message := msg.Params[1]

	for _, targetString := range targets {
		target, cerr := CasefoldChannel(targetString)
		if cerr == nil {
			channel := server.channels.Get(target)
			if channel == nil {
				// errors silently ignored with NOTICE as per RFC
				continue
			}
			channel.PrivMsg(clientOnlyTags, client, message)
		} else {
			target, err := CasefoldName(targetString)
			if err != nil {
				continue
			}

			user := server.clients.Get(target)
			if user == nil {
				// errors silently ignored with NOTICE as per RFC
				continue
			}
			if !user.capabilities[MessageTags] {
				clientOnlyTags = nil
			}
			user.SendFromClient(client, clientOnlyTags, client.nickMaskString, "NOTICE", user.nick, message)
		}
	}
	return false
}

// KICK <channel>{,<channel>} <user>{,<user>} [<comment>]
func kickHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	channels := strings.Split(msg.Params[0], ",")
	users := strings.Split(msg.Params[1], ",")
	if (len(channels) != len(users)) && (len(users) != 1) {
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, "KICK", "Not enough parameters")
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
		casefoldedChname, err := CasefoldChannel(chname)
		channel := server.channels.Get(casefoldedChname)
		if err != nil || channel == nil {
			client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, chname, "No such channel")
			continue
		}

		casefoldedNickname, err := CasefoldName(nickname)
		target := server.clients.Get(casefoldedNickname)
		if err != nil || target == nil {
			client.Send(nil, server.name, ERR_NOSUCHNICK, nickname, "No such nick")
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
			client.Send(nil, client.server.name, ERR_CHANOPRIVSNEEDED, chname, "You're not a channel operator")
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
		client.Send(nil, server.name, ERR_NOSUCHSERVER, client.nick, target, "No such server")
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
			casefoldedChname, err := CasefoldChannel(chname)
			channel := server.channels.Get(casefoldedChname)
			if err != nil || channel == nil || (!client.flags[Operator] && channel.flags[Secret]) {
				client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, chname, "No such channel")
				continue
			}
			client.RplList(channel)
		}
	}
	client.Send(nil, server.name, RPL_LISTEND, client.nick, "End of LIST")
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

	target.Send(nil, target.server.name, RPL_LIST, target.nick, channel.name, string(memberCount), channel.topic)
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
		casefoldedChname, err := CasefoldChannel(chname)
		channel := server.channels.Get(casefoldedChname)
		if err != nil || channel == nil {
			client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, chname, "No such channel")
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
	casefoldedTarget, err := Casefold(target)
	if (target != "") && err != nil || (casefoldedTarget != server.nameCasefolded) {
		client.Send(nil, server.name, ERR_NOSUCHSERVER, client.nick, target, "No such server")
		return false
	}

	client.Send(nil, server.name, RPL_VERSION, client.nick, Ver, server.name)
	client.RplISupport()
	return false
}

// INVITE <nickname> <channel>
func inviteHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	nickname := msg.Params[0]
	channelName := msg.Params[1]

	casefoldedNickname, err := CasefoldName(nickname)
	target := server.clients.Get(casefoldedNickname)
	if err != nil || target == nil {
		client.Send(nil, server.name, ERR_NOSUCHNICK, client.nick, nickname, "No such nick")
		return false
	}

	casefoldedChannelName, err := CasefoldChannel(channelName)
	channel := server.channels.Get(casefoldedChannelName)
	if err != nil || channel == nil {
		client.Send(nil, server.name, RPL_INVITING, client.nick, target.nick, channelName)
		target.Send(nil, client.nickMaskString, "INVITE", target.nick, channel.name)
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
	casefoldedTarget, err := Casefold(target)
	if (target != "") && err != nil || (casefoldedTarget != server.nameCasefolded) {
		client.Send(nil, server.name, ERR_NOSUCHSERVER, client.nick, target, "No such server")
		return false
	}
	client.Send(nil, server.name, RPL_TIME, client.nick, server.name, time.Now().Format(time.RFC1123))
	return false
}

// KILL <nickname> <comment>
func killHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	nickname := msg.Params[0]
	comment := "<no reason supplied>"
	if len(msg.Params) > 1 {
		comment = msg.Params[1]
	}

	casefoldedNickname, err := CasefoldName(nickname)
	target := server.clients.Get(casefoldedNickname)
	if err != nil || target == nil {
		client.Send(nil, client.server.name, ERR_NOSUCHNICK, nickname, "No such nick")
		return false
	}

	quitMsg := fmt.Sprintf("Killed (%s (%s))", client.nick, comment)
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
		results := server.whoWas.Find(nickname, count)
		if len(results) == 0 {
			client.Send(nil, server.name, ERR_WASNOSUCHNICK, client.nick, nickname, "There was no such nickname")
		} else {
			for _, whoWas := range results {
				client.Send(nil, server.name, RPL_WHOWASUSER, client.nick, whoWas.nickname, whoWas.username, whoWas.hostname, "*", whoWas.realname)
			}
		}
		client.Send(nil, server.name, RPL_ENDOFWHOWAS, client.nick, nickname, "End of WHOWAS")
	}
	return false
}
