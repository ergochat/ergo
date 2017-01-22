// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/DanielOaks/girc-go/ircmsg"
	"github.com/tidwall/buntdb"
)

var (
	// cached because this may be used lots
	tooManyClientsMsg      = ircmsg.MakeMessage(nil, "", "ERROR", "Too many clients from your network")
	tooManyClientsBytes, _ = tooManyClientsMsg.Line()

	bannedFromServerMsg      = ircmsg.MakeMessage(nil, "", "ERROR", "You are banned from this server (%s)")
	bannedFromServerBytes, _ = bannedFromServerMsg.Line()

	errDbOutOfDate = errors.New("Database schema is old.")
)

// Limits holds the maximum limits for various things such as topic lengths.
type Limits struct {
	AwayLen        int
	ChannelLen     int
	KickLen        int
	MonitorEntries int
	NickLen        int
	TopicLen       int
	ChanListModes  int
	LineLen        LineLenLimits
}

// LineLenLimits holds the maximum limits for IRC lines.
type LineLenLimits struct {
	Tags int
	Rest int
}

// ListenerInterface represents an interface for a listener.
type ListenerInterface struct {
	Listener net.Listener
	Events   chan ListenerEvent
}

const (
	// DestroyListener instructs the listener to destroy itself.
	DestroyListener ListenerEventType = iota
	// UpdateListener instructs the listener to update itself (grab new certs, etc).
	UpdateListener = iota
)

// ListenerEventType is the type of event this is.
type ListenerEventType int

// ListenerEvent is an event that's passed to the listener.
type ListenerEvent struct {
	Type      ListenerEventType
	NewConfig *tls.Config
}

// Server is the main Oragono server.
type Server struct {
	accountRegistration     *AccountRegistration
	accounts                map[string]*ClientAccount
	authenticationEnabled   bool
	channels                ChannelNameMap
	checkIdent              bool
	clients                 *ClientLookupSet
	commands                chan Command
	configFilename          string
	connectionThrottle      *ConnectionThrottle
	connectionThrottleMutex sync.Mutex // used when affecting the connection limiter, to make sure rehashing doesn't make things go out-of-whack
	connectionLimits        *ConnectionLimits
	connectionLimitsMutex   sync.Mutex // used when affecting the connection limiter, to make sure rehashing doesn't make things go out-of-whack
	ctime                   time.Time
	currentOpers            map[*Client]bool
	dlines                  *DLineManager
	idle                    chan *Client
	isupport                *ISupportList
	klines                  *KLineManager
	limits                  Limits
	listenerEventActMutex   sync.Mutex
	listeners               map[string]ListenerInterface
	listenerUpdateMutex     sync.Mutex
	monitoring              map[string][]Client
	motdLines               []string
	name                    string
	nameCasefolded          string
	networkName             string
	newConns                chan clientConn
	operators               map[string]Oper
	operclasses             map[string]OperClass
	password                []byte
	passwords               *PasswordManager
	rehashMutex             sync.Mutex
	rehashSignal            chan os.Signal
	restAPI                 *RestAPIConfig
	signals                 chan os.Signal
	store                   *buntdb.DB
	whoWas                  *WhoWasList
}

var (
	// ServerExitSignals are the signals the server will exit on.
	ServerExitSignals = []os.Signal{
		syscall.SIGINT,
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

	// startup check that we have HELP entries for every command
	for name := range Commands {
		_, exists := Help[strings.ToLower(name)]
		if !exists {
			log.Fatal("Help entry does not exist for ", name)
		}
	}

	if config.AuthenticationEnabled {
		SupportedCapabilities[SASL] = true
	}

	if config.Limits.LineLen.Tags > 512 || config.Limits.LineLen.Rest > 512 {
		SupportedCapabilities[MaxLine] = true
		CapValues[MaxLine] = fmt.Sprintf("%d,%d", config.Limits.LineLen.Tags, config.Limits.LineLen.Rest)
	}

	operClasses, err := config.OperatorClasses()
	if err != nil {
		log.Fatal("Error loading oper classes:", err.Error())
	}
	opers, err := config.Operators(operClasses)
	if err != nil {
		log.Fatal("Error loading operators:", err.Error())
	}

	connectionLimits, err := NewConnectionLimits(config.Server.ConnectionLimits)
	if err != nil {
		log.Fatal("Error loading connection limits:", err.Error())
	}
	connectionThrottle, err := NewConnectionThrottle(config.Server.ConnectionThrottle)
	if err != nil {
		log.Fatal("Error loading connection throttler:", err.Error())
	}

	server := &Server{
		accounts:              make(map[string]*ClientAccount),
		authenticationEnabled: config.AuthenticationEnabled,
		channels:              make(ChannelNameMap),
		clients:               NewClientLookupSet(),
		commands:              make(chan Command),
		configFilename:        configFilename,
		connectionLimits:      connectionLimits,
		connectionThrottle:    connectionThrottle,
		ctime:                 time.Now(),
		currentOpers:          make(map[*Client]bool),
		idle:                  make(chan *Client),
		limits: Limits{
			AwayLen:        int(config.Limits.AwayLen),
			ChannelLen:     int(config.Limits.ChannelLen),
			KickLen:        int(config.Limits.KickLen),
			MonitorEntries: int(config.Limits.MonitorEntries),
			NickLen:        int(config.Limits.NickLen),
			TopicLen:       int(config.Limits.TopicLen),
			ChanListModes:  int(config.Limits.ChanListModes),
			LineLen: LineLenLimits{
				Tags: config.Limits.LineLen.Tags,
				Rest: config.Limits.LineLen.Rest,
			},
		},
		listeners:      make(map[string]ListenerInterface),
		monitoring:     make(map[string][]Client),
		name:           config.Server.Name,
		nameCasefolded: casefoldedName,
		networkName:    config.Network.Name,
		newConns:       make(chan clientConn),
		operclasses:    *operClasses,
		operators:      opers,
		signals:        make(chan os.Signal, len(ServerExitSignals)),
		rehashSignal:   make(chan os.Signal, 1),
		restAPI:        &config.Server.RestAPI,
		whoWas:         NewWhoWasList(config.Limits.WhowasEntries),
		checkIdent:     config.Server.CheckIdent,
	}

	// open data store
	db, err := buntdb.Open(config.Datastore.Path)
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to open datastore: %s", err.Error()))
	}
	server.store = db

	// check db version
	err = server.store.View(func(tx *buntdb.Tx) error {
		version, _ := tx.Get(keySchemaVersion)
		if version != latestDbSchema {
			log.Println(fmt.Sprintf("Database must be updated. Expected schema v%s, got v%s.", latestDbSchema, version))
			return errDbOutOfDate
		}
		return nil
	})
	if err != nil {
		// close the db
		db.Close()
		return nil
	}

	// load *lines
	server.loadDLines()
	server.loadKLines()

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
		server.createListener(addr, config.TLSListeners())
	}

	if config.Server.Wslisten != "" {
		server.wslisten(config.Server.Wslisten, config.Server.TLSListeners)
	}

	// registration
	accountReg := NewAccountRegistration(config.Registration.Accounts)
	server.accountRegistration = &accountReg

	// Attempt to clean up when receiving these signals.
	signal.Notify(server.signals, ServerExitSignals...)
	signal.Notify(server.rehashSignal, syscall.SIGHUP)

	server.setISupport()

	// start API if enabled
	if server.restAPI.Enabled {
		Log.info.Printf("%s rest API started on %s .", server.name, server.restAPI.Listen)
		server.startRestAPI()
	}

	return server
}

// setISupport sets up our RPL_ISUPPORT reply.
func (server *Server) setISupport() {
	maxTargetsString := strconv.Itoa(maxTargets)

	// add RPL_ISUPPORT tokens
	server.isupport = NewISupportList()
	server.isupport.Add("AWAYLEN", strconv.Itoa(server.limits.AwayLen))
	server.isupport.Add("CASEMAPPING", casemappingName)
	server.isupport.Add("CHANMODES", strings.Join([]string{ChannelModes{BanMask, ExceptMask, InviteMask}.String(), "", ChannelModes{UserLimit, Key}.String(), ChannelModes{InviteOnly, Moderated, NoOutside, OpOnlyTopic, ChanRoleplaying, Secret}.String()}, ","))
	server.isupport.Add("CHANNELLEN", strconv.Itoa(server.limits.ChannelLen))
	server.isupport.Add("CHANTYPES", "#")
	server.isupport.Add("EXCEPTS", "")
	server.isupport.Add("INVEX", "")
	server.isupport.Add("KICKLEN", strconv.Itoa(server.limits.KickLen))
	server.isupport.Add("MAXLIST", fmt.Sprintf("beI:%s", strconv.Itoa(server.limits.ChanListModes)))
	server.isupport.Add("MAXTARGETS", maxTargetsString)
	server.isupport.Add("MODES", "")
	server.isupport.Add("MONITOR", strconv.Itoa(server.limits.MonitorEntries))
	server.isupport.Add("NETWORK", server.networkName)
	server.isupport.Add("NICKLEN", strconv.Itoa(server.limits.NickLen))
	server.isupport.Add("PREFIX", "(qaohv)~&@%+")
	server.isupport.Add("RPCHAN", "E")
	server.isupport.Add("RPUSER", "E")
	server.isupport.Add("STATUSMSG", "~&@%+")
	server.isupport.Add("TARGMAX", fmt.Sprintf("NAMES:1,LIST:1,KICK:1,WHOIS:1,PRIVMSG:%s,TAGMSG:%s,NOTICE:%s,MONITOR:", maxTargetsString, maxTargetsString, maxTargetsString))
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
	server.clients.ByNickMutex.RLock()
	for _, client := range server.clients.ByNick {
		client.Notice("Server is shutting down")
	}
	server.clients.ByNickMutex.RUnlock()

	if err := server.store.Close(); err != nil {
		Log.error.Println("Server.Shutdown store.Close: error:", err)
	}
}

// Run starts the server.
func (server *Server) Run() {
	// defer closing db/store
	defer server.store.Close()

	done := false
	for !done {
		select {
		case <-server.signals:
			server.Shutdown()
			done = true

		case <-server.rehashSignal:
			// eventually we expect to use HUP to reload config
			err := server.rehash()
			if err != nil {
				Log.error.Println("Failed to rehash:", err.Error())
			}

		case conn := <-server.newConns:
			// check connection limits
			ipaddr := net.ParseIP(IPString(conn.Conn.RemoteAddr()))
			if ipaddr != nil {
				// check DLINEs
				isBanned, info := server.dlines.CheckIP(ipaddr)
				if isBanned {
					banMessage := fmt.Sprintf(bannedFromServerBytes, info.Reason)
					if info.Time != nil {
						banMessage += fmt.Sprintf(" [%s]", info.Time.Duration.String())
					}
					conn.Conn.Write([]byte(banMessage))
					conn.Conn.Close()
					continue
				}

				// check connection limits
				server.connectionLimitsMutex.Lock()
				err := server.connectionLimits.AddClient(ipaddr, false)
				server.connectionLimitsMutex.Unlock()
				if err != nil {
					// too many connections from one client, tell the client and close the connection
					// this might not show up properly on some clients, but our objective here is just to close it out before it has a load impact on us
					conn.Conn.Write([]byte(tooManyClientsBytes))
					conn.Conn.Close()
					continue
				}

				// check connection throttle
				server.connectionThrottleMutex.Lock()
				err = server.connectionThrottle.AddClient(ipaddr)
				server.connectionThrottleMutex.Unlock()
				if err != nil {
					// too many connections too quickly from client, tell them and close the connection
					length := &IPRestrictTime{
						Duration: server.connectionThrottle.BanDuration,
						Expires:  time.Now().Add(server.connectionThrottle.BanDuration),
					}
					server.dlines.AddIP(ipaddr, length, server.connectionThrottle.BanMessage, "Exceeded automated connection throttle")

					// reset ban on connectionThrottle
					server.connectionThrottle.ResetFor(ipaddr)

					// this might not show up properly on some clients, but our objective here is just to close it out before it has a load impact on us
					conn.Conn.Write([]byte(server.connectionThrottle.BanMessageBytes))
					conn.Conn.Close()
					continue
				}

				go NewClient(server, conn.Conn, conn.IsTLS)
				continue
			}

		case client := <-server.idle:
			client.Idle()
		}
	}
}

//
// IRC protocol listeners
//

// createListener starts the given listeners.
func (server *Server) createListener(addr string, tlsMap map[string]*tls.Config) {
	config, listenTLS := tlsMap[addr]

	_, alreadyExists := server.listeners[addr]
	if alreadyExists {
		log.Fatal(server, "listener already exists:", addr)
	}

	// make listener event channel
	listenerEventChannel := make(chan ListenerEvent, 1)

	// make listener
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(server, "listen error: ", err)
	}

	tlsString := "plaintext"
	if listenTLS {
		config.ClientAuth = tls.RequestClientCert
		listener = tls.NewListener(listener, config)
		tlsString = "TLS"
	}

	// throw our details to the server so we can be modified/killed later
	li := ListenerInterface{
		Events:   listenerEventChannel,
		Listener: listener,
	}
	server.listeners[addr] = li

	// start listening
	Log.info.Printf("%s listening on %s using %s.", server.name, addr, tlsString)

	// setup accept goroutine
	go func() {
		for {
			conn, err := listener.Accept()

			if err == nil {
				newConn := clientConn{
					Conn:  conn,
					IsTLS: listenTLS,
				}

				server.newConns <- newConn
			}

			select {
			case event := <-server.listeners[addr].Events:
				// this is used to confirm that whoever passed us this event has closed the existing listener correctly (in an attempt to get us to notice the event).
				// this is required to keep REHASH from having a very small race possibility of killing the primary listener
				server.listenerEventActMutex.Lock()
				server.listenerEventActMutex.Unlock()

				if event.Type == DestroyListener {
					// listener should already be closed, this is just for safety
					listener.Close()
					return
				} else if event.Type == UpdateListener {
					// close old listener
					listener.Close()

					// make new listener
					listener, err = net.Listen("tcp", addr)
					if err != nil {
						log.Fatal(server, "listen error: ", err)
					}

					tlsString := "plaintext"
					if event.NewConfig != nil {
						config = event.NewConfig
						config.ClientAuth = tls.RequestClientCert
						listener = tls.NewListener(listener, config)
						tlsString = "TLS"
					}

					// update server ListenerInterface
					li.Listener = listener
					server.listenerUpdateMutex.Lock()
					server.listeners[addr] = li
					server.listenerUpdateMutex.Unlock()

					// print notice
					Log.info.Printf("%s updated listener %s using %s.", server.name, addr, tlsString)
				}
			default:
				// no events waiting for us, fall-through and continue
			}
		}
	}()
}

//
// websocket listen goroutine
//

func (server *Server) wslisten(addr string, tlsMap map[string]*TLSListenConfig) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			Log.error.Printf("%s method not allowed", server.name)
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
			Log.error.Printf("%s websocket upgrade error: %s", server.name, err)
			return
		}

		newConn := clientConn{
			Conn:  WSContainer{ws},
			IsTLS: false, //TODO(dan): track TLS or not here properly
		}
		server.newConns <- newConn
	})
	go func() {
		config, listenTLS := tlsMap[addr]

		tlsString := "plaintext"
		var err error
		if listenTLS {
			tlsString = "TLS"
		}
		Log.info.Printf("%s websocket listening on %s using %s.", server.name, addr, tlsString)

		if listenTLS {
			err = http.ListenAndServeTLS(addr, config.Cert, config.Key, nil)
		} else {
			err = http.ListenAndServe(addr, nil)
		}
		if err != nil {
			Log.error.Printf("%s listenAndServe (%s) error: %s", server.name, tlsString, err)
		}
	}()
}

// generateMessageID returns a network-unique message ID.
func (server *Server) generateMessageID() string {
	return fmt.Sprintf("%s-%s", strconv.FormatInt(time.Now().UTC().UnixNano(), 10), strconv.FormatInt(rand.Int63(), 10))
}

//
// server functionality
//

func (server *Server) tryRegister(c *Client) {
	if c.registered || !c.HasNick() || !c.HasUsername() ||
		(c.capState == CapNegotiating) {
		return
	}

	// check KLINEs
	isBanned, info := server.klines.CheckMasks(c.AllNickmasks()...)
	if isBanned {
		reason := info.Reason
		if info.Time != nil {
			reason += fmt.Sprintf(" [%s]", info.Time.Duration.String())
		}
		c.Send(nil, "", "ERROR", fmt.Sprintf("You are banned from this server (%s)", reason))
		c.quitMessageSent = true
		c.destroy()
		return
	}

	// continue registration
	c.Register()

	// send welcome text
	//NOTE(dan): we specifically use the NICK here instead of the nickmask
	// see http://modern.ircdocs.horse/#rplwelcome-001 for details on why we avoid using the nickmask
	c.Send(nil, server.name, RPL_WELCOME, c.nick, fmt.Sprintf("Welcome to the Internet Relay Network %s", c.nick))
	c.Send(nil, server.name, RPL_YOURHOST, c.nick, fmt.Sprintf("Your host is %s, running version %s", server.name, Ver))
	c.Send(nil, server.name, RPL_CREATED, c.nick, fmt.Sprintf("This server was created %s", server.ctime.Format(time.RFC1123)))
	//TODO(dan): Look at adding last optional [<channel modes with a parameter>] parameter
	c.Send(nil, server.name, RPL_MYINFO, c.nick, server.name, Ver, supportedUserModesString, supportedChannelModesString)
	c.RplISupport()
	server.MOTD(c)
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

func (server *Server) Id() string {
	return server.name
}

func (server *Server) Nick() string {
	return server.Id()
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

	if !client.HasUsername() {
		client.username = "~" + msg.Params[0]
		// don't bother updating nickmask here, it's not valid anyway
	}
	if client.realname == "" {
		client.realname = msg.Params[3]
	}

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
			if len(name) > 0 {
				client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, name, "No such channel")
			}
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
			if len(chname) > 0 {
				client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, chname, "No such channel")
			}
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
		if len(msg.Params[0]) > 0 {
			client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, msg.Params[0], "No such channel")
		}
		return false
	}

	if len(msg.Params) > 1 {
		channel.SetTopic(client, msg.Params[1])
	} else {
		channel.GetTopic(client)
	}
	return false
}

func wordWrap(text string, lineWidth int) []string {
	var lines []string
	var cacheLine, cacheWord string

	for _, char := range text {
		if (char == ' ' || char == '-') && len(cacheLine)+len(cacheWord)+1 < lineWidth {
			cacheLine += cacheWord + string(char)
			cacheWord = ""
		} else if len(cacheLine)+len(cacheWord)+1 >= lineWidth {
			if len(cacheLine) < (lineWidth / 2) {
				// there must be a really long word or something, just split on word boundary
				cacheLine += cacheWord + string(char)
				cacheWord = ""
			}
			lines = append(lines, cacheLine)
			cacheLine = ""
		} else {
			cacheWord += string(char)
		}
	}
	if len(cacheWord) > 0 {
		cacheLine += cacheWord
	}
	if len(cacheLine) > 0 {
		lines = append(lines, cacheLine)
	}

	return lines
}

// SplitMessage represents a message that's been split for sending.
type SplitMessage struct {
	For512     []string
	ForMaxLine string
}

func (server *Server) splitMessage(original string, origIs512 bool) SplitMessage {
	var newSplit SplitMessage

	newSplit.ForMaxLine = original

	if !origIs512 {
		newSplit.For512 = wordWrap(original, 400)
	} else {
		newSplit.For512 = []string{original}
	}

	return newSplit
}

// PRIVMSG <target>{,<target>} <message>
func privmsgHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	clientOnlyTags := GetClientOnlyTags(msg.Tags)
	targets := strings.Split(msg.Params[0], ",")
	message := msg.Params[1]

	// split privmsg
	splitMsg := server.splitMessage(message, !client.capabilities[MaxLine])

	for i, targetString := range targets {
		// max of four targets per privmsg
		if i > maxTargets-1 {
			break
		}
		prefixes, targetString := SplitChannelMembershipPrefixes(targetString)
		lowestPrefix := GetLowestChannelModePrefix(prefixes)

		// eh, no need to notify them
		if len(targetString) < 1 {
			continue
		}

		target, err := CasefoldChannel(targetString)
		if err == nil {
			channel := server.channels.Get(target)
			if channel == nil {
				client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, targetString, "No such channel")
				continue
			}
			msgid := server.generateMessageID()
			channel.SplitPrivMsg(msgid, lowestPrefix, clientOnlyTags, client, splitMsg)
		} else {
			target, err = CasefoldName(targetString)
			user := server.clients.Get(target)
			if err != nil || user == nil {
				if len(target) > 0 {
					client.Send(nil, server.name, ERR_NOSUCHNICK, target, "No such nick")
				}
				continue
			}
			if !user.capabilities[MessageTags] {
				clientOnlyTags = nil
			}
			msgid := server.generateMessageID()
			user.SendSplitMsgFromClient(msgid, client, clientOnlyTags, "PRIVMSG", user.nick, splitMsg)
			if client.capabilities[EchoMessage] {
				client.SendSplitMsgFromClient(msgid, client, clientOnlyTags, "PRIVMSG", user.nick, splitMsg)
			}
			if user.flags[Away] {
				//TODO(dan): possibly implement cooldown of away notifications to users
				client.Send(nil, server.name, RPL_AWAY, user.nick, user.awayMessage)
			}
		}
	}
	return false
}

// TAGMSG <target>{,<target>}
func tagmsgHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	clientOnlyTags := GetClientOnlyTags(msg.Tags)
	// no client-only tags, so we can drop it
	if clientOnlyTags == nil {
		return false
	}

	targets := strings.Split(msg.Params[0], ",")

	for i, targetString := range targets {
		// max of four targets per privmsg
		if i > maxTargets-1 {
			break
		}
		prefixes, targetString := SplitChannelMembershipPrefixes(targetString)
		lowestPrefix := GetLowestChannelModePrefix(prefixes)

		// eh, no need to notify them
		if len(targetString) < 1 {
			continue
		}

		target, err := CasefoldChannel(targetString)
		if err == nil {
			channel := server.channels.Get(target)
			if channel == nil {
				client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, targetString, "No such channel")
				continue
			}
			msgid := server.generateMessageID()

			channel.TagMsg(msgid, lowestPrefix, clientOnlyTags, client)
		} else {
			target, err = CasefoldName(targetString)
			user := server.clients.Get(target)
			if err != nil || user == nil {
				if len(target) > 0 {
					client.Send(nil, server.name, ERR_NOSUCHNICK, target, "No such nick")
				}
				continue
			}
			msgid := server.generateMessageID()

			// end user can't receive tagmsgs
			if !user.capabilities[MessageTags] {
				continue
			}
			user.SendFromClient(msgid, client, clientOnlyTags, "TAGMSG", user.nick)
			if client.capabilities[EchoMessage] {
				client.SendFromClient(msgid, client, clientOnlyTags, "TAGMSG", user.nick)
			}
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
		channel.membersMutex.RLock()
		defer channel.membersMutex.RUnlock()

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

	if len(strings.TrimSpace(masksString)) < 1 {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, "No masks given")
		return false
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
		// only get the first request
		casefoldedMask, err := Casefold(strings.Split(masksString, ",")[0])
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

	whoischannels := client.WhoisChannelsNames(target)
	if whoischannels != nil {
		// the dodgy +" " hack here is to work around some silly clients that don't parse trailing params correctly. This forces last param to be a trailing always.
		client.Send(nil, client.server.name, RPL_WHOISCHANNELS, client.nick, target.nick, strings.Join(whoischannels, " ")+" ")
	}
	if target.class != nil {
		client.Send(nil, client.server.name, RPL_WHOISOPERATOR, client.nick, target.nick, target.whoisLine)
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
		channel.membersMutex.RLock()
		defer channel.membersMutex.RUnlock()

		flags += channel.members[client].Prefixes(target.capabilities[MultiPrefix])
		channelName = channel.name
	}
	target.Send(nil, target.server.name, RPL_WHOREPLY, target.nick, channelName, client.username, client.hostname, client.server.name, client.nick, flags, strconv.Itoa(client.hops)+" "+client.realname)
}

func whoChannel(client *Client, channel *Channel, friends ClientSet) {
	channel.membersMutex.RLock()
	defer channel.membersMutex.RUnlock()

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
	hash := server.operators[name].Pass
	password := []byte(msg.Params[1])

	err = ComparePassword(hash, password)

	if (hash == nil) || (err != nil) {
		client.Send(nil, server.name, ERR_PASSWDMISMATCH, client.nick, "Password incorrect")
		return true
	}

	client.flags[Operator] = true
	client.operName = name
	client.class = server.operators[name].Class
	server.currentOpers[client] = true
	client.whoisLine = server.operators[name].WhoisLine

	// push new vhost if one is set
	if len(server.operators[name].Vhost) > 0 {
		for fClient := range client.Friends(ChgHost) {
			fClient.SendFromClient("", client, nil, "CHGHOST", client.username, server.operators[name].Vhost)
		}
		// CHGHOST requires prefix nickmask to have original hostname, so do that before updating nickmask
		client.vhost = server.operators[name].Vhost
		client.updateNickMask()
	}

	client.Send(nil, server.name, RPL_YOUREOPER, client.nick, "You are now an IRC operator")
	//TODO(dan): Should this be sent automagically as part of setting the flag/mode?
	modech := ModeChanges{&ModeChange{
		mode: Operator,
		op:   Add,
	}}
	client.Send(nil, server.name, "MODE", client.nick, modech.String())
	return false
}

// rehash reloads the config and applies the changes from the config file.
func (server *Server) rehash() error {
	// only let one REHASH go on at a time
	server.rehashMutex.Lock()

	config, err := LoadConfig(server.configFilename)

	if err != nil {
		return fmt.Errorf("Error rehashing config file config: %s", err.Error())
	}

	// line lengths cannot be changed after launching the server
	if server.limits.LineLen.Tags != config.Limits.LineLen.Tags || server.limits.LineLen.Rest != config.Limits.LineLen.Rest {
		return fmt.Errorf("Maximum line length (linelen) cannot be changed after launching the server, rehash aborted")
	}

	// confirm connectionLimits are fine
	connectionLimits, err := NewConnectionLimits(config.Server.ConnectionLimits)
	if err != nil {
		return fmt.Errorf("Error rehashing config file connection-limits: %s", err.Error())
	}

	// confirm connectionThrottler is fine
	connectionThrottle, err := NewConnectionThrottle(config.Server.ConnectionThrottle)
	if err != nil {
		return fmt.Errorf("Error rehashing config file connection-throttle: %s", err.Error())
	}

	// confirm operator stuff all exists and is fine
	operclasses, err := config.OperatorClasses()
	if err != nil {
		return fmt.Errorf("Error rehashing config file operclasses: %s", err.Error())
	}
	opers, err := config.Operators(operclasses)
	if err != nil {
		return fmt.Errorf("Error rehashing config file opers: %s", err.Error())
	}
	for client := range server.currentOpers {
		_, exists := opers[client.operName]
		if !exists {
			return fmt.Errorf("Oper [%s] no longer exists (used by client [%s])", client.operName, client.nickMaskString)
		}
	}

	// apply new connectionlimits
	server.connectionLimitsMutex.Lock()
	server.connectionLimits = connectionLimits
	server.connectionThrottleMutex.Lock()
	server.connectionThrottle = connectionThrottle

	server.clients.ByNickMutex.RLock()
	for _, client := range server.clients.ByNick {
		ipaddr := net.ParseIP(IPString(client.socket.conn.RemoteAddr()))
		if ipaddr != nil {
			server.connectionLimits.AddClient(ipaddr, true)
		}
	}
	server.clients.ByNickMutex.RUnlock()
	server.connectionLimitsMutex.Unlock()

	// setup new and removed caps
	addedCaps := make(CapabilitySet)
	removedCaps := make(CapabilitySet)

	// SASL
	if config.AuthenticationEnabled && !server.authenticationEnabled {
		// enabling SASL
		SupportedCapabilities[SASL] = true
		addedCaps[SASL] = true
	}
	if !config.AuthenticationEnabled && server.authenticationEnabled {
		// disabling SASL
		SupportedCapabilities[SASL] = false
		removedCaps[SASL] = true
	}
	server.authenticationEnabled = config.AuthenticationEnabled

	// burst new and removed caps
	var capBurstClients ClientSet
	added := make(map[CapVersion]string)
	var removed string

	if len(addedCaps) > 0 || len(removedCaps) > 0 {
		capBurstClients = server.clients.AllWithCaps(CapNotify)

		added[Cap301] = addedCaps.String(Cap301)
		added[Cap302] = addedCaps.String(Cap302)
		// removed never has values
		removed = removedCaps.String(Cap301)
	}

	for sClient := range capBurstClients {
		if len(addedCaps) > 0 {
			sClient.Send(nil, server.name, "CAP", sClient.nick, "NEW", added[sClient.capVersion])
		}
		if len(removedCaps) > 0 {
			sClient.Send(nil, server.name, "CAP", sClient.nick, "DEL", removed)
		}
	}

	// set server options
	server.limits = Limits{
		AwayLen:        int(config.Limits.AwayLen),
		ChannelLen:     int(config.Limits.ChannelLen),
		KickLen:        int(config.Limits.KickLen),
		MonitorEntries: int(config.Limits.MonitorEntries),
		NickLen:        int(config.Limits.NickLen),
		TopicLen:       int(config.Limits.TopicLen),
		ChanListModes:  int(config.Limits.ChanListModes),
	}
	server.operclasses = *operclasses
	server.operators = opers
	server.checkIdent = config.Server.CheckIdent

	// registration
	accountReg := NewAccountRegistration(config.Registration.Accounts)
	server.accountRegistration = &accountReg

	// set RPL_ISUPPORT
	oldISupportList := server.isupport
	server.setISupport()
	newISupportReplies := oldISupportList.GetDifference(server.isupport)

	// push new info to all of our clients
	server.clients.ByNickMutex.RLock()
	for _, sClient := range server.clients.ByNick {
		for _, tokenline := range newISupportReplies {
			// ugly trickery ahead
			sClient.Send(nil, server.name, RPL_ISUPPORT, append([]string{sClient.nick}, tokenline...)...)
		}
	}
	server.clients.ByNickMutex.RUnlock()

	// destroy old listeners
	tlsListeners := config.TLSListeners()
	for addr := range server.listeners {
		var exists bool
		for _, newaddr := range config.Server.Listen {
			if newaddr == addr {
				exists = true
				break
			}
		}

		server.listenerEventActMutex.Lock()
		if exists {
			// update old listener
			server.listeners[addr].Events <- ListenerEvent{
				Type:      UpdateListener,
				NewConfig: tlsListeners[addr],
			}
		} else {
			// destroy nonexistent listener
			server.listeners[addr].Events <- ListenerEvent{
				Type: DestroyListener,
			}
		}
		// force listener to apply the event right away
		server.listeners[addr].Listener.Close()

		server.listenerEventActMutex.Unlock()
	}

	for _, newaddr := range config.Server.Listen {
		_, exists := server.listeners[newaddr]
		if !exists {
			// make new listener
			server.createListener(newaddr, tlsListeners)
		}
	}

	server.rehashMutex.Unlock()
	return nil
}

// REHASH
func rehashHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	err := server.rehash()

	if err == nil {
		client.Send(nil, server.name, RPL_REHASHING, client.nick, "ircd.yaml", "Rehashing")
	} else {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, "REHASH", err.Error())
	}
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
			friend.SendFromClient("", client, nil, "AWAY", client.awayMessage)
		} else {
			friend.SendFromClient("", client, nil, "AWAY")
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

	// split privmsg
	splitMsg := server.splitMessage(message, !client.capabilities[MaxLine])

	for i, targetString := range targets {
		// max of four targets per privmsg
		if i > maxTargets-1 {
			break
		}
		prefixes, targetString := SplitChannelMembershipPrefixes(targetString)
		lowestPrefix := GetLowestChannelModePrefix(prefixes)

		target, cerr := CasefoldChannel(targetString)
		if cerr == nil {
			channel := server.channels.Get(target)
			if channel == nil {
				// errors silently ignored with NOTICE as per RFC
				continue
			}
			msgid := server.generateMessageID()
			channel.SplitNotice(msgid, lowestPrefix, clientOnlyTags, client, splitMsg)
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
			msgid := server.generateMessageID()
			user.SendSplitMsgFromClient(msgid, client, clientOnlyTags, "NOTICE", user.nick, splitMsg)
			if client.capabilities[EchoMessage] {
				client.SendSplitMsgFromClient(msgid, client, clientOnlyTags, "NOTICE", user.nick, splitMsg)
			}
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

	var kicks [][]string
	for index, channel := range channels {
		if len(users) == 1 {
			kicks = append(kicks, []string{channel, users[0]})
		} else {
			kicks = append(kicks, []string{channel, users[index]})
		}
	}

	var comment string
	if len(msg.Params) > 2 {
		comment = msg.Params[2]
	}
	for _, info := range kicks {
		chname := info[0]
		nickname := info[1]
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
		channel.membersMutex.Lock()

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
			channel.kickNoMutex(client, target, comment)
		} else {
			client.Send(nil, client.server.name, ERR_CHANOPRIVSNEEDED, chname, "You're not a channel operator")
		}

		channel.membersMutex.Unlock()
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
		// limit regular users to only listing one channel
		if !client.flags[Operator] {
			channels = channels[:1]
		}

		for _, chname := range channels {
			casefoldedChname, err := CasefoldChannel(chname)
			channel := server.channels.Get(casefoldedChname)
			if err != nil || channel == nil || (!client.flags[Operator] && channel.flags[Secret]) {
				if len(chname) > 0 {
					client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, chname, "No such channel")
				}
				continue
			}
			client.RplList(channel)
		}
	}
	client.Send(nil, server.name, RPL_LISTEND, client.nick, "End of LIST")
	return false
}

func (target *Client) RplList(channel *Channel) {
	channel.membersMutex.RLock()
	defer channel.membersMutex.RUnlock()

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

	target.Send(nil, target.server.name, RPL_LIST, target.nick, channel.name, strconv.Itoa(memberCount), channel.topic)
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

	// limit regular users to only listing one channel
	if !client.flags[Operator] {
		channels = channels[:1]
	}

	for _, chname := range channels {
		casefoldedChname, err := CasefoldChannel(chname)
		channel := server.channels.Get(casefoldedChname)
		if err != nil || channel == nil {
			if len(chname) > 0 {
				client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, chname, "No such channel")
			}
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
	if target != "" && (err != nil || casefoldedTarget != server.nameCasefolded) {
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
			if len(nickname) > 0 {
				client.Send(nil, server.name, ERR_WASNOSUCHNICK, client.nick, nickname, "There was no such nickname")
			}
		} else {
			for _, whoWas := range results {
				client.Send(nil, server.name, RPL_WHOWASUSER, client.nick, whoWas.nickname, whoWas.username, whoWas.hostname, "*", whoWas.realname)
			}
		}
		if len(nickname) > 0 {
			client.Send(nil, server.name, RPL_ENDOFWHOWAS, client.nick, nickname, "End of WHOWAS")
		}
	}
	return false
}

// LUSERS [<mask> [<server>]]
func lusersHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	//TODO(vegax87) Fix network statistics and additional parameters
	var totalcount, invisiblecount, opercount int

	server.clients.ByNickMutex.RLock()
	defer server.clients.ByNickMutex.RUnlock()

	for _, onlineusers := range server.clients.ByNick {
		totalcount++
		if onlineusers.flags[Invisible] {
			invisiblecount++
		}
		if onlineusers.flags[Operator] {
			opercount++
		}
	}
	client.Send(nil, server.name, RPL_LUSERCLIENT, client.nick, fmt.Sprintf("There are %d users and %d invisible on %d server(s)", totalcount, invisiblecount, 1))
	client.Send(nil, server.name, RPL_LUSEROP, client.nick, fmt.Sprintf("%d operators online", opercount))
	client.Send(nil, server.name, RPL_LUSERCHANNELS, client.nick, fmt.Sprintf("%d channels formed", len(server.channels)))
	client.Send(nil, server.name, RPL_LUSERME, client.nick, fmt.Sprintf("I have %d clients and %d servers", totalcount, 1))
	return false
}
