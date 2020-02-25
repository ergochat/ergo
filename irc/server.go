// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/oragono/oragono/irc/caps"
	"github.com/oragono/oragono/irc/connection_limits"
	"github.com/oragono/oragono/irc/history"
	"github.com/oragono/oragono/irc/logger"
	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/mysql"
	"github.com/oragono/oragono/irc/sno"
	"github.com/tidwall/buntdb"
)

var (
	// common error line to sub values into
	errorMsg = "ERROR :%s\r\n"

	// supportedUserModesString acts as a cache for when we introduce users
	supportedUserModesString = modes.SupportedUserModes.String()
	// supportedChannelModesString acts as a cache for when we introduce users
	supportedChannelModesString = modes.SupportedChannelModes.String()

	// whitelist of caps to serve on the STS-only listener. In particular,
	// never advertise SASL, to discourage people from sending their passwords:
	stsOnlyCaps = caps.NewSet(caps.STS, caps.MessageTags, caps.ServerTime, caps.LabeledResponse, caps.Nope)

	// we only have standard channels for now. TODO: any updates to this
	// will also need to be reflected in CasefoldChannel
	chanTypes = "#"

	throttleMessage = "You have attempted to connect too many times within a short duration. Wait a while, and you will be able to connect."
)

// ListenerWrapper wraps a listener so it can be safely reconfigured or stopped
type ListenerWrapper struct {
	// protects atomic update of config and shouldStop:
	sync.Mutex // tier 1
	listener   net.Listener
	config     listenerConfig
	shouldStop bool
}

// Server is the main Oragono server.
type Server struct {
	accounts          AccountManager
	channels          ChannelManager
	channelRegistry   ChannelRegistry
	clients           ClientManager
	config            unsafe.Pointer
	configFilename    string
	connectionLimiter connection_limits.Limiter
	ctime             time.Time
	dlines            *DLineManager
	helpIndexManager  HelpIndexManager
	klines            *KLineManager
	listeners         map[string]*ListenerWrapper
	logger            *logger.Manager
	monitorManager    MonitorManager
	name              string
	nameCasefolded    string
	rehashMutex       sync.Mutex // tier 4
	rehashSignal      chan os.Signal
	pprofServer       *http.Server
	resumeManager     ResumeManager
	signals           chan os.Signal
	snomasks          SnoManager
	store             *buntdb.DB
	historyDB         mysql.MySQL
	torLimiter        connection_limits.TorLimiter
	whoWas            WhoWasList
	stats             Stats
	semaphores        ServerSemaphores
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
	Conn   net.Conn
	Config listenerConfig
}

// NewServer returns a new Oragono server.
func NewServer(config *Config, logger *logger.Manager) (*Server, error) {
	// initialize data structures
	server := &Server{
		ctime:        time.Now().UTC(),
		listeners:    make(map[string]*ListenerWrapper),
		logger:       logger,
		rehashSignal: make(chan os.Signal, 1),
		signals:      make(chan os.Signal, len(ServerExitSignals)),
	}

	server.clients.Initialize()
	server.semaphores.Initialize()
	server.resumeManager.Initialize(server)
	server.whoWas.Initialize(config.Limits.WhowasEntries)
	server.monitorManager.Initialize()
	server.snomasks.Initialize()

	if err := server.applyConfig(config); err != nil {
		return nil, err
	}

	// Attempt to clean up when receiving these signals.
	signal.Notify(server.signals, ServerExitSignals...)
	signal.Notify(server.rehashSignal, syscall.SIGHUP)

	return server, nil
}

// Shutdown shuts down the server.
func (server *Server) Shutdown() {
	//TODO(dan): Make sure we disallow new nicks
	for _, client := range server.clients.AllClients() {
		client.Notice("Server is shutting down")
	}

	if err := server.store.Close(); err != nil {
		server.logger.Error("shutdown", fmt.Sprintln("Could not close datastore:", err))
	}

	server.historyDB.Close()
}

// Run starts the server.
func (server *Server) Run() {
	// defer closing db/store
	defer server.store.Close()

	for {
		select {
		case <-server.signals:
			server.Shutdown()
			return

		case <-server.rehashSignal:
			go func() {
				server.logger.Info("server", "Rehashing due to SIGHUP")
				err := server.rehash()
				if err != nil {
					server.logger.Error("server", fmt.Sprintln("Failed to rehash:", err.Error()))
				}
			}()
		}
	}
}

func (server *Server) checkBans(ipaddr net.IP) (banned bool, message string) {
	// check DLINEs
	isBanned, info := server.dlines.CheckIP(ipaddr)
	if isBanned {
		server.logger.Info("localconnect-ip", fmt.Sprintf("Client from %v rejected by d-line", ipaddr))
		return true, info.BanMessage("You are banned from this server (%s)")
	}

	// check connection limits
	err := server.connectionLimiter.AddClient(ipaddr)
	if err == connection_limits.ErrLimitExceeded {
		// too many connections from one client, tell the client and close the connection
		server.logger.Info("localconnect-ip", fmt.Sprintf("Client from %v rejected for connection limit", ipaddr))
		return true, "Too many clients from your network"
	} else if err == connection_limits.ErrThrottleExceeded {
		duration := server.Config().Server.IPLimits.BanDuration
		if duration == 0 {
			return false, ""
		}
		server.dlines.AddIP(ipaddr, duration, throttleMessage, "Exceeded automated connection throttle", "auto.connection.throttler")
		// they're DLINE'd for 15 minutes or whatever, so we can reset the connection throttle now,
		// and once their temporary DLINE is finished they can fill up the throttler again
		server.connectionLimiter.ResetThrottle(ipaddr)

		// this might not show up properly on some clients, but our objective here is just to close it out before it has a load impact on us
		server.logger.Info(
			"localconnect-ip",
			fmt.Sprintf("Client from %v exceeded connection throttle, d-lining for %v", ipaddr, duration))
		return true, throttleMessage
	} else if err != nil {
		server.logger.Warning("internal", "unexpected ban result", err.Error())
	}

	return false, ""
}

func (server *Server) checkTorLimits() (banned bool, message string) {
	switch server.torLimiter.AddClient() {
	case connection_limits.ErrLimitExceeded:
		return true, "Too many clients from the Tor network"
	case connection_limits.ErrThrottleExceeded:
		return true, "Exceeded connection throttle for the Tor network"
	default:
		return false, ""
	}
}

//
// IRC protocol listeners
//

// createListener starts a given listener.
func (server *Server) createListener(addr string, conf listenerConfig, bindMode os.FileMode) (*ListenerWrapper, error) {
	// make listener
	var listener net.Listener
	var err error
	addr = strings.TrimPrefix(addr, "unix:")
	if strings.HasPrefix(addr, "/") {
		// https://stackoverflow.com/a/34881585
		os.Remove(addr)
		listener, err = net.Listen("unix", addr)
		if err == nil && bindMode != 0 {
			os.Chmod(addr, bindMode)
		}
	} else {
		listener, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return nil, err
	}

	// throw our details to the server so we can be modified/killed later
	wrapper := ListenerWrapper{
		listener:   listener,
		config:     conf,
		shouldStop: false,
	}

	var shouldStop bool

	// setup accept goroutine
	go func() {
		for {
			conn, err := listener.Accept()

			// synchronously access config data:
			wrapper.Lock()
			shouldStop = wrapper.shouldStop
			conf := wrapper.config
			wrapper.Unlock()

			if shouldStop {
				if conn != nil {
					conn.Close()
				}
				listener.Close()
				return
			} else if err == nil {
				var proxyLine string
				if conf.ProxyBeforeTLS {
					proxyLine = readRawProxyLine(conn)
					if proxyLine == "" {
						server.logger.Error("internal", "bad TLS-proxy line from", addr)
						conn.Close()
						continue
					}
				}
				if conf.TLSConfig != nil {
					conn = tls.Server(conn, conf.TLSConfig)
				}
				newConn := clientConn{
					Conn:   conn,
					Config: conf,
				}
				// hand off the connection
				go server.RunClient(newConn, proxyLine)
			} else {
				server.logger.Error("internal", "accept error", addr, err.Error())
			}
		}
	}()

	return &wrapper, nil
}

//
// server functionality
//

func (server *Server) tryRegister(c *Client, session *Session) (exiting bool) {
	// if the session just sent us a RESUME line, try to resume
	if session.resumeDetails != nil {
		session.tryResume()
		return // whether we succeeded or failed, either way `c` is not getting registered
	}

	// try to complete registration normally
	if c.preregNick == "" || !c.HasUsername() || session.capState == caps.NegotiatingState {
		return
	}

	if c.isSTSOnly {
		server.playRegistrationBurst(session)
		return true
	}

	// client MUST send PASS if necessary, or authenticate with SASL if necessary,
	// before completing the other registration commands
	authOutcome := c.isAuthorized(server.Config(), session)
	var quitMessage string
	switch authOutcome {
	case authFailPass:
		quitMessage = c.t("Password incorrect")
		c.Send(nil, server.name, ERR_PASSWDMISMATCH, "*", quitMessage)
	case authFailSaslRequired, authFailTorSaslRequired:
		quitMessage = c.t("You must log in with SASL to join this server")
		c.Send(nil, c.server.name, "FAIL", "*", "ACCOUNT_REQUIRED", quitMessage)
	}
	if authOutcome != authSuccess {
		c.Quit(quitMessage, nil)
		return true
	}

	// we have the final value of the IP address: do the hostname lookup
	// (nickmask will be set below once nickname assignment succeeds)
	if session.rawHostname == "" {
		session.client.lookupHostname(session, false)
	}

	rb := NewResponseBuffer(session)
	nickAssigned := performNickChange(server, c, c, session, c.preregNick, rb)
	rb.Send(true)
	if !nickAssigned {
		c.preregNick = ""
		return
	}

	if session.client != c {
		// reattached, bail out.
		// we'll play the reg burst later, on the new goroutine associated with
		// (thisSession, otherClient). This is to avoid having to transfer state
		// like nickname, hostname, etc. to show the correct values in the reg burst.
		return
	}

	// check KLINEs
	isBanned, info := server.klines.CheckMasks(c.AllNickmasks()...)
	if isBanned {
		c.Quit(info.BanMessage(c.t("You are banned from this server (%s)")), nil)
		return true
	}

	// registration has succeeded:
	c.SetRegistered()

	// count new user in statistics
	server.stats.Register()
	server.monitorManager.AlertAbout(c, true)

	server.playRegistrationBurst(session)
	return false
}

func (server *Server) playRegistrationBurst(session *Session) {
	c := session.client
	// continue registration
	d := c.Details()
	server.logger.Info("localconnect", fmt.Sprintf("Client connected [%s] [u:%s] [r:%s]", d.nick, d.username, d.realname))
	server.snomasks.Send(sno.LocalConnects, fmt.Sprintf("Client connected [%s] [u:%s] [h:%s] [ip:%s] [r:%s]", d.nick, d.username, session.rawHostname, session.IP().String(), d.realname))

	// send welcome text
	//NOTE(dan): we specifically use the NICK here instead of the nickmask
	// see http://modern.ircdocs.horse/#rplwelcome-001 for details on why we avoid using the nickmask
	session.Send(nil, server.name, RPL_WELCOME, d.nick, fmt.Sprintf(c.t("Welcome to the Internet Relay Network %s"), d.nick))
	session.Send(nil, server.name, RPL_YOURHOST, d.nick, fmt.Sprintf(c.t("Your host is %[1]s, running version %[2]s"), server.name, Ver))
	session.Send(nil, server.name, RPL_CREATED, d.nick, fmt.Sprintf(c.t("This server was created %s"), server.ctime.Format(time.RFC1123)))
	//TODO(dan): Look at adding last optional [<channel modes with a parameter>] parameter
	session.Send(nil, server.name, RPL_MYINFO, d.nick, server.name, Ver, supportedUserModesString, supportedChannelModesString)

	if c.isSTSOnly {
		for _, line := range server.Config().Server.STS.bannerLines {
			c.Notice(line)
		}
		return
	}

	rb := NewResponseBuffer(session)
	server.RplISupport(c, rb)
	server.Lusers(c, rb)
	server.MOTD(c, rb)
	rb.Send(true)

	modestring := c.ModeString()
	if modestring != "+" {
		session.Send(nil, d.nickMask, RPL_UMODEIS, d.nick, modestring)
	}

	c.attemptAutoOper(session)

	if server.logger.IsLoggingRawIO() {
		session.Send(nil, c.server.name, "NOTICE", d.nick, c.t("This server is in debug mode and is logging all user I/O. If you do not wish for everything you send to be readable by the server owner(s), please disconnect."))
	}

	// #572: defer nick warnings to the end of the registration burst
	session.client.nickTimer.Touch(nil)
}

// RplISupport outputs our ISUPPORT lines to the client. This is used on connection and in VERSION responses.
func (server *Server) RplISupport(client *Client, rb *ResponseBuffer) {
	translatedISupport := client.t("are supported by this server")
	nick := client.Nick()
	config := server.Config()
	for _, cachedTokenLine := range config.Server.isupport.CachedReply {
		length := len(cachedTokenLine) + 2
		tokenline := make([]string, length)
		tokenline[0] = nick
		copy(tokenline[1:], cachedTokenLine)
		tokenline[length-1] = translatedISupport
		rb.Add(nil, server.name, RPL_ISUPPORT, tokenline...)
	}
}

func (server *Server) Lusers(client *Client, rb *ResponseBuffer) {
	nick := client.Nick()
	stats := server.stats.GetValues()

	rb.Add(nil, server.name, RPL_LUSERCLIENT, nick, fmt.Sprintf(client.t("There are %[1]d users and %[2]d invisible on %[3]d server(s)"), stats.Total-stats.Invisible, stats.Invisible, 1))
	rb.Add(nil, server.name, RPL_LUSEROP, nick, strconv.Itoa(stats.Operators), client.t("IRC Operators online"))
	rb.Add(nil, server.name, RPL_LUSERUNKNOWN, nick, strconv.Itoa(stats.Unknown), client.t("unregistered connections"))
	rb.Add(nil, server.name, RPL_LUSERCHANNELS, nick, strconv.Itoa(server.channels.Len()), client.t("channels formed"))
	rb.Add(nil, server.name, RPL_LUSERME, nick, fmt.Sprintf(client.t("I have %[1]d clients and %[2]d servers"), stats.Total, 1))
	total := strconv.Itoa(stats.Total)
	max := strconv.Itoa(stats.Max)
	rb.Add(nil, server.name, RPL_LOCALUSERS, nick, total, max, fmt.Sprintf(client.t("Current local users %[1]s, max %[2]s"), total, max))
	rb.Add(nil, server.name, RPL_GLOBALUSERS, nick, total, max, fmt.Sprintf(client.t("Current global users %[1]s, max %[2]s"), total, max))
}

// MOTD serves the Message of the Day.
func (server *Server) MOTD(client *Client, rb *ResponseBuffer) {
	motdLines := server.Config().Server.motdLines

	if len(motdLines) < 1 {
		rb.Add(nil, server.name, ERR_NOMOTD, client.nick, client.t("MOTD File is missing"))
		return
	}

	rb.Add(nil, server.name, RPL_MOTDSTART, client.nick, fmt.Sprintf(client.t("- %s Message of the day - "), server.name))
	for _, line := range motdLines {
		rb.Add(nil, server.name, RPL_MOTD, client.nick, line)
	}
	rb.Add(nil, server.name, RPL_ENDOFMOTD, client.nick, client.t("End of MOTD command"))
}

// WhoisChannelsNames returns the common channel names between two users.
func (client *Client) WhoisChannelsNames(target *Client, multiPrefix bool) []string {
	var chstrs []string
	for _, channel := range target.Channels() {
		// channel is secret and the target can't see it
		if !client.HasMode(modes.Operator) {
			if (target.HasMode(modes.Invisible) || channel.flags.HasMode(modes.Secret)) && !channel.hasClient(client) {
				continue
			}
		}
		chstrs = append(chstrs, channel.ClientPrefixes(target, multiPrefix)+channel.name)
	}
	return chstrs
}

func (client *Client) getWhoisOf(target *Client, rb *ResponseBuffer) {
	cnick := client.Nick()
	targetInfo := target.Details()
	rb.Add(nil, client.server.name, RPL_WHOISUSER, cnick, targetInfo.nick, targetInfo.username, targetInfo.hostname, "*", targetInfo.realname)
	tnick := targetInfo.nick

	whoischannels := client.WhoisChannelsNames(target, rb.session.capabilities.Has(caps.MultiPrefix))
	if whoischannels != nil {
		rb.Add(nil, client.server.name, RPL_WHOISCHANNELS, cnick, tnick, strings.Join(whoischannels, " "))
	}
	tOper := target.Oper()
	if tOper != nil {
		rb.Add(nil, client.server.name, RPL_WHOISOPERATOR, cnick, tnick, tOper.WhoisLine)
	}
	if client.HasMode(modes.Operator) || client == target {
		rb.Add(nil, client.server.name, RPL_WHOISACTUALLY, cnick, tnick, fmt.Sprintf("%s@%s", targetInfo.username, target.RawHostname()), target.IPString(), client.t("Actual user@host, Actual IP"))
	}
	if target.HasMode(modes.TLS) {
		rb.Add(nil, client.server.name, RPL_WHOISSECURE, cnick, tnick, client.t("is using a secure connection"))
	}
	if targetInfo.accountName != "*" {
		rb.Add(nil, client.server.name, RPL_WHOISACCOUNT, cnick, tnick, targetInfo.accountName, client.t("is logged in as"))
	}
	if target.HasMode(modes.Bot) {
		rb.Add(nil, client.server.name, RPL_WHOISBOT, cnick, tnick, ircfmt.Unescape(fmt.Sprintf(client.t("is a $bBot$b on %s"), client.server.Config().Network.Name)))
	}

	if client == target || client.HasMode(modes.Operator) {
		for _, session := range target.Sessions() {
			if session.certfp != "" {
				rb.Add(nil, client.server.name, RPL_WHOISCERTFP, cnick, tnick, fmt.Sprintf(client.t("has client certificate fingerprint %s"), session.certfp))
			}
		}
	}
	rb.Add(nil, client.server.name, RPL_WHOISIDLE, cnick, tnick, strconv.FormatUint(target.IdleSeconds(), 10), strconv.FormatInt(target.SignonTime(), 10), client.t("seconds idle, signon time"))
}

// rplWhoReply returns the WHO reply between one user and another channel/user.
// <channel> <user> <host> <server> <nick> ( "H" / "G" ) ["*"] [ ( "@" / "+" ) ]
// :<hopcount> <real name>
func (client *Client) rplWhoReply(channel *Channel, target *Client, rb *ResponseBuffer) {
	channelName := "*"
	flags := ""

	if target.Away() {
		flags = "G"
	} else {
		flags = "H"
	}
	if target.HasMode(modes.Operator) {
		flags += "*"
	}

	if channel != nil {
		// TODO is this right?
		flags += channel.ClientPrefixes(target, rb.session.capabilities.Has(caps.MultiPrefix))
		channelName = channel.name
	}
	details := target.Details()
	// hardcode a hopcount of 0 for now
	rb.Add(nil, client.server.name, RPL_WHOREPLY, client.Nick(), channelName, details.username, details.hostname, client.server.name, details.nick, flags, "0 "+details.realname)
}

// rehash reloads the config and applies the changes from the config file.
func (server *Server) rehash() error {
	server.logger.Debug("server", "Starting rehash")

	// only let one REHASH go on at a time
	server.rehashMutex.Lock()
	defer server.rehashMutex.Unlock()

	server.logger.Debug("server", "Got rehash lock")

	config, err := LoadConfig(server.configFilename)
	if err != nil {
		return fmt.Errorf("Error loading config file config: %s", err.Error())
	}

	err = server.applyConfig(config)
	if err != nil {
		return fmt.Errorf("Error applying config changes: %s", err.Error())
	}

	return nil
}

func (server *Server) applyConfig(config *Config) (err error) {
	oldConfig := server.Config()
	initial := oldConfig == nil

	if initial {
		server.configFilename = config.Filename
		server.name = config.Server.Name
		server.nameCasefolded = config.Server.nameCasefolded
		globalCasemappingSetting = config.Server.Casemapping
	} else {
		// enforce configs that can't be changed after launch:
		if server.name != config.Server.Name {
			return fmt.Errorf("Server name cannot be changed after launching the server, rehash aborted")
		} else if oldConfig.Datastore.Path != config.Datastore.Path {
			return fmt.Errorf("Datastore path cannot be changed after launching the server, rehash aborted")
		} else if globalCasemappingSetting != config.Server.Casemapping {
			return fmt.Errorf("Casemapping cannot be changed after launching the server, rehash aborted")
		}
	}

	server.logger.Info("server", "Using config file", server.configFilename)

	// first, reload config sections for functionality implemented in subpackages:
	wasLoggingRawIO := !initial && server.logger.IsLoggingRawIO()
	err = server.logger.ApplyConfig(config.Logging)
	if err != nil {
		return err
	}
	nowLoggingRawIO := server.logger.IsLoggingRawIO()
	// notify existing clients if raw i/o logging was enabled by a rehash
	sendRawOutputNotice := !wasLoggingRawIO && nowLoggingRawIO

	server.connectionLimiter.ApplyConfig(&config.Server.IPLimits)

	tlConf := &config.Server.TorListeners
	server.torLimiter.Configure(tlConf.MaxConnections, tlConf.ThrottleDuration, tlConf.MaxConnectionsPerDuration)

	// Translations
	server.logger.Debug("server", "Regenerating HELP indexes for new languages")
	server.helpIndexManager.GenerateIndices(config.languageManager)

	if oldConfig != nil {
		// if certain features were enabled by rehash, we need to load the corresponding data
		// from the store
		if !oldConfig.Accounts.NickReservation.Enabled {
			server.accounts.buildNickToAccountIndex(config)
		}
		if !oldConfig.Accounts.VHosts.Enabled {
			server.accounts.initVHostRequestQueue(config)
		}
		if !oldConfig.Channels.Registration.Enabled {
			server.channels.loadRegisteredChannels(config)
		}
		// resize history buffers as needed
		if oldConfig.History != config.History {
			for _, channel := range server.channels.Channels() {
				channel.resizeHistory(config)
			}
			for _, client := range server.clients.AllClients() {
				client.resizeHistory(config)
			}
		}
	}

	// activate the new config
	server.SetConfig(config)

	// burst new and removed caps
	addedCaps, removedCaps := config.Diff(oldConfig)
	var capBurstSessions []*Session
	added := make(map[caps.Version][]string)
	var removed []string

	if !addedCaps.Empty() || !removedCaps.Empty() {
		capBurstSessions = server.clients.AllWithCapsNotify()

		added[caps.Cap301] = addedCaps.Strings(caps.Cap301, config.Server.capValues, 0)
		added[caps.Cap302] = addedCaps.Strings(caps.Cap302, config.Server.capValues, 0)
		// removed never has values, so we leave it as Cap301
		removed = removedCaps.Strings(caps.Cap301, config.Server.capValues, 0)
	}

	for _, sSession := range capBurstSessions {
		// DEL caps and then send NEW ones so that updated caps get removed/added correctly
		if !removedCaps.Empty() {
			for _, capStr := range removed {
				sSession.Send(nil, server.name, "CAP", sSession.client.Nick(), "DEL", capStr)
			}
		}
		if !addedCaps.Empty() {
			for _, capStr := range added[sSession.capVersion] {
				sSession.Send(nil, server.name, "CAP", sSession.client.Nick(), "NEW", capStr)
			}
		}
	}

	server.logger.Info("server", "Using datastore", config.Datastore.Path)
	if initial {
		if err := server.loadDatastore(config); err != nil {
			return err
		}
	} else {
		if config.Datastore.MySQL.Enabled && config.Datastore.MySQL != oldConfig.Datastore.MySQL {
			server.historyDB.SetConfig(config.Datastore.MySQL)
		}
	}

	server.setupPprofListener(config)

	// set RPL_ISUPPORT
	var newISupportReplies [][]string
	if oldConfig != nil {
		newISupportReplies = oldConfig.Server.isupport.GetDifference(&config.Server.isupport)
	}

	// we are now open for business
	err = server.setupListeners(config)

	if !initial {
		// push new info to all of our clients
		for _, sClient := range server.clients.AllClients() {
			for _, tokenline := range newISupportReplies {
				sClient.Send(nil, server.name, RPL_ISUPPORT, append([]string{sClient.nick}, tokenline...)...)
			}

			if sendRawOutputNotice {
				sClient.Notice(sClient.t("This server is in debug mode and is logging all user I/O. If you do not wish for everything you send to be readable by the server owner(s), please disconnect."))
			}

			if !oldConfig.Accounts.NickReservation.Enabled && config.Accounts.NickReservation.Enabled {
				sClient.nickTimer.Initialize(sClient)
				sClient.nickTimer.Touch(nil)
			} else if oldConfig.Accounts.NickReservation.Enabled && !config.Accounts.NickReservation.Enabled {
				sClient.nickTimer.Stop()
			}
		}
	}

	return err
}

func (server *Server) setupPprofListener(config *Config) {
	pprofListener := ""
	if config.Debug.PprofListener != nil {
		pprofListener = *config.Debug.PprofListener
	}
	if server.pprofServer != nil {
		if pprofListener == "" || (pprofListener != server.pprofServer.Addr) {
			server.logger.Info("server", "Stopping pprof listener", server.pprofServer.Addr)
			server.pprofServer.Close()
			server.pprofServer = nil
		}
	}
	if pprofListener != "" && server.pprofServer == nil {
		ps := http.Server{
			Addr: pprofListener,
		}
		go func() {
			if err := ps.ListenAndServe(); err != nil {
				server.logger.Error("server", "pprof listener failed", err.Error())
			}
		}()
		server.pprofServer = &ps
		server.logger.Info("server", "Started pprof listener", server.pprofServer.Addr)
	}
}

func (config *Config) loadMOTD() (err error) {
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

				if config.Server.MOTDFormatting {
					line = ircfmt.Unescape(line)
				}

				// "- " is the required prefix for MOTD, we just add it here to make
				// bursting it out to clients easier
				line = fmt.Sprintf("- %s", line)

				config.Server.motdLines = append(config.Server.motdLines, line)
			}
		}
	}
	return
}

func (server *Server) loadDatastore(config *Config) error {
	// open the datastore and load server state for which it (rather than config)
	// is the source of truth

	_, err := os.Stat(config.Datastore.Path)
	if os.IsNotExist(err) {
		server.logger.Warning("server", "database does not exist, creating it", config.Datastore.Path)
		err = initializeDB(config.Datastore.Path)
		if err != nil {
			return err
		}
	}

	db, err := OpenDatabase(config)
	if err == nil {
		server.store = db
	} else {
		return fmt.Errorf("Failed to open datastore: %s", err.Error())
	}

	// load *lines (from the datastores)
	server.logger.Debug("server", "Loading D/Klines")
	server.loadDLines()
	server.loadKLines()

	server.channelRegistry.Initialize(server)
	server.channels.Initialize(server)
	server.accounts.Initialize(server)

	if config.Datastore.MySQL.Enabled {
		server.historyDB.Initialize(server.logger, config.Datastore.MySQL)
		err = server.historyDB.Open()
		if err != nil {
			server.logger.Error("internal", "could not connect to mysql", err.Error())
			return err
		}
	}

	return nil
}

func (server *Server) setupListeners(config *Config) (err error) {
	logListener := func(addr string, config listenerConfig) {
		server.logger.Info("listeners",
			fmt.Sprintf("now listening on %s, tls=%t, tlsproxy=%t, tor=%t.", addr, (config.TLSConfig != nil), config.ProxyBeforeTLS, config.Tor),
		)
	}

	// update or destroy all existing listeners
	for addr := range server.listeners {
		currentListener := server.listeners[addr]
		newConfig, stillConfigured := config.Server.trueListeners[addr]

		currentListener.Lock()
		currentListener.shouldStop = !stillConfigured
		currentListener.config = newConfig
		currentListener.Unlock()

		if stillConfigured {
			logListener(addr, newConfig)
		} else {
			// tell the listener it should stop by interrupting its Accept() call:
			currentListener.listener.Close()
			delete(server.listeners, addr)
			server.logger.Info("listeners", fmt.Sprintf("stopped listening on %s.", addr))
		}
	}

	publicPlaintextListener := ""
	// create new listeners that were not previously configured
	for newAddr, newConfig := range config.Server.trueListeners {
		if strings.HasPrefix(newAddr, ":") && !newConfig.Tor && !newConfig.STSOnly && newConfig.TLSConfig == nil {
			publicPlaintextListener = newAddr
		}
		_, exists := server.listeners[newAddr]
		if !exists {
			// make new listener
			listener, listenerErr := server.createListener(newAddr, newConfig, config.Server.UnixBindMode)
			if listenerErr != nil {
				server.logger.Error("server", "couldn't listen on", newAddr, listenerErr.Error())
				err = listenerErr
				continue
			}
			server.listeners[newAddr] = listener
			logListener(newAddr, newConfig)
		}
	}

	if publicPlaintextListener != "" {
		server.logger.Warning("listeners", fmt.Sprintf("Your server is configured with public plaintext listener %s. Consider disabling it for improved security and privacy.", publicPlaintextListener))
	}

	return
}

// Gets the abstract sequence from which we're going to query history;
// we may already know the channel we're querying, or we may have
// to look it up via a string target. This function is responsible for
// privilege checking.
func (server *Server) GetHistorySequence(providedChannel *Channel, client *Client, target string) (channel *Channel, sequence history.Sequence, err error) {
	config := server.Config()
	// 4 cases: {persistent, ephemeral} x {normal, conversation}
	// with ephemeral history, recipient is implicit in the choice of `hist`,
	// and sender is "" if we're retrieving a channel or *, and the correspondent's name
	// if we're retrieving a DM conversation ("query buffer"). with persistent history,
	// recipient is always nonempty, and sender is either empty or nonempty as before.
	var status HistoryStatus
	var sender, recipient string
	var hist *history.Buffer
	channel = providedChannel
	if channel == nil {
		if strings.HasPrefix(target, "#") {
			channel = server.channels.Get(target)
			if channel == nil {
				return
			}
		}
	}
	if channel != nil {
		if !channel.hasClient(client) {
			err = errInsufficientPrivs
			return
		}
		status, recipient = channel.historyStatus(config)
		switch status {
		case HistoryEphemeral:
			hist = &channel.history
		case HistoryPersistent:
			// already set `recipient`
		default:
			return
		}
	} else {
		status, recipient = client.historyStatus(config)
		if target != "*" {
			sender, err = CasefoldName(target)
			if err != nil {
				return
			}
		}
		switch status {
		case HistoryEphemeral:
			hist = &client.history
		case HistoryPersistent:
			// already set `recipient`, and `sender` if necessary
		default:
			return
		}
	}

	var cutoff time.Time
	if config.History.Restrictions.ExpireTime != 0 {
		cutoff = time.Now().UTC().Add(-time.Duration(config.History.Restrictions.ExpireTime))
	}
	if config.History.Restrictions.EnforceRegistrationDate {
		regCutoff := client.historyCutoff()
		// take the later of the two cutoffs
		if regCutoff.After(cutoff) {
			cutoff = regCutoff
		}
	}
	if !cutoff.IsZero() {
		cutoff = cutoff.Add(-time.Duration(config.History.Restrictions.GracePeriod))
	}

	if hist != nil {
		sequence = hist.MakeSequence(sender, cutoff)
	} else if recipient != "" {
		sequence = server.historyDB.MakeSequence(sender, recipient, cutoff)
	}
	return
}

// elistMatcher takes and matches ELIST conditions
type elistMatcher struct {
	MinClientsActive bool
	MinClients       int
	MaxClientsActive bool
	MaxClients       int
}

// Matches checks whether the given channel matches our matches.
func (matcher *elistMatcher) Matches(channel *Channel) bool {
	if matcher.MinClientsActive {
		if len(channel.Members()) < matcher.MinClients {
			return false
		}
	}

	if matcher.MaxClientsActive {
		if len(channel.Members()) < len(channel.members) {
			return false
		}
	}

	return true
}

// RplList returns the RPL_LIST numeric for the given channel.
func (target *Client) RplList(channel *Channel, rb *ResponseBuffer) {
	// get the correct number of channel members
	var memberCount int
	if target.HasMode(modes.Operator) || channel.hasClient(target) {
		memberCount = len(channel.Members())
	} else {
		for _, member := range channel.Members() {
			if !member.HasMode(modes.Invisible) {
				memberCount++
			}
		}
	}

	rb.Add(nil, target.server.name, RPL_LIST, target.nick, channel.name, strconv.Itoa(memberCount), channel.topic)
}

var (
	infoString1 = strings.Split(`      ▄▄▄   ▄▄▄·  ▄▄ •        ▐ ▄
▪     ▀▄ █·▐█ ▀█ ▐█ ▀ ▪▪     •█▌▐█▪     
 ▄█▀▄ ▐▀▀▄ ▄█▀▀█ ▄█ ▀█▄ ▄█▀▄▪▐█▐▐▌ ▄█▀▄ 
▐█▌.▐▌▐█•█▌▐█ ▪▐▌▐█▄▪▐█▐█▌ ▐▌██▐█▌▐█▌.▐▌
 ▀█▄▀▪.▀  ▀ ▀  ▀ ·▀▀▀▀  ▀█▄▀ ▀▀ █▪ ▀█▄▀▪

         https://oragono.io/
   https://github.com/oragono/oragono
   https://crowdin.com/project/oragono
`, "\n")
	infoString2 = strings.Split(`    Daniel Oakley,          DanielOaks,    <daniel@danieloaks.net>
    Shivaram Lingamneni,    slingamn,      <slingamn@cs.stanford.edu>
`, "\n")
	infoString3 = strings.Split(`    3onyc
    Edmund Huber
    Euan Kemp (euank)
    Jeremy Latt
    Martin Lindhe (martinlindhe)
    Roberto Besser (besser)
    Robin Burchell (rburchell)
    Sean Enck (enckse)
    soul9
    Vegax
`, "\n")
)
