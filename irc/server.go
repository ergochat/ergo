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
	"github.com/oragono/oragono/irc/logger"
	"github.com/oragono/oragono/irc/modes"
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

	// SupportedCapabilities are the caps we advertise.
	// MaxLine, SASL and STS may be unset during server startup / rehash.
	SupportedCapabilities = caps.NewCompleteSet()

	// CapValues are the actual values we advertise to v3.2 clients.
	// actual values are set during server startup.
	CapValues = caps.NewValues()
)

// ListenerWrapper wraps a listener so it can be safely reconfigured or stopped
type ListenerWrapper struct {
	listener   net.Listener
	tlsConfig  *tls.Config
	isTor      bool
	shouldStop bool
	// protects atomic update of tlsConfig and shouldStop:
	configMutex sync.Mutex // tier 1
}

// Server is the main Oragono server.
type Server struct {
	accounts            AccountManager
	channels            ChannelManager
	channelRegistry     ChannelRegistry
	clients             ClientManager
	config              unsafe.Pointer
	configFilename      string
	connectionLimiter   connection_limits.Limiter
	connectionThrottler connection_limits.Throttler
	ctime               time.Time
	dlines              *DLineManager
	helpIndexManager    HelpIndexManager
	klines              *KLineManager
	listeners           map[string]*ListenerWrapper
	logger              *logger.Manager
	monitorManager      MonitorManager
	name                string
	nameCasefolded      string
	rehashMutex         sync.Mutex // tier 4
	rehashSignal        chan os.Signal
	pprofServer         *http.Server
	resumeManager       ResumeManager
	signals             chan os.Signal
	snomasks            SnoManager
	store               *buntdb.DB
	torLimiter          connection_limits.TorLimiter
	whoWas              WhoWasList
	stats               Stats
	semaphores          ServerSemaphores
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
	IsTor bool
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

	if err := server.applyConfig(config, true); err != nil {
		return nil, err
	}

	// Attempt to clean up when receiving these signals.
	signal.Notify(server.signals, ServerExitSignals...)
	signal.Notify(server.rehashSignal, syscall.SIGHUP)

	return server, nil
}

// setISupport sets up our RPL_ISUPPORT reply.
func (config *Config) generateISupport() (err error) {
	maxTargetsString := strconv.Itoa(maxTargets)

	// add RPL_ISUPPORT tokens
	isupport := &config.Server.isupport
	isupport.Initialize()
	isupport.Add("AWAYLEN", strconv.Itoa(config.Limits.AwayLen))
	isupport.Add("CASEMAPPING", "ascii")
	isupport.Add("CHANMODES", strings.Join([]string{modes.Modes{modes.BanMask, modes.ExceptMask, modes.InviteMask}.String(), "", modes.Modes{modes.UserLimit, modes.Key}.String(), modes.Modes{modes.InviteOnly, modes.Moderated, modes.NoOutside, modes.OpOnlyTopic, modes.ChanRoleplaying, modes.Secret}.String()}, ","))
	if config.History.Enabled && config.History.ChathistoryMax > 0 {
		isupport.Add("draft/CHATHISTORY", strconv.Itoa(config.History.ChathistoryMax))
	}
	isupport.Add("CHANNELLEN", strconv.Itoa(config.Limits.ChannelLen))
	isupport.Add("CHANTYPES", "#")
	isupport.Add("ELIST", "U")
	isupport.Add("EXCEPTS", "")
	isupport.Add("INVEX", "")
	isupport.Add("KICKLEN", strconv.Itoa(config.Limits.KickLen))
	isupport.Add("MAXLIST", fmt.Sprintf("beI:%s", strconv.Itoa(config.Limits.ChanListModes)))
	isupport.Add("MAXTARGETS", maxTargetsString)
	isupport.Add("MODES", "")
	isupport.Add("MONITOR", strconv.Itoa(config.Limits.MonitorEntries))
	isupport.Add("NETWORK", config.Network.Name)
	isupport.Add("NICKLEN", strconv.Itoa(config.Limits.NickLen))
	isupport.Add("PREFIX", "(qaohv)~&@%+")
	isupport.Add("RPCHAN", "E")
	isupport.Add("RPUSER", "E")
	isupport.Add("STATUSMSG", "~&@%+")
	isupport.Add("TARGMAX", fmt.Sprintf("NAMES:1,LIST:1,KICK:1,WHOIS:1,USERHOST:10,PRIVMSG:%s,TAGMSG:%s,NOTICE:%s,MONITOR:", maxTargetsString, maxTargetsString, maxTargetsString))
	isupport.Add("TOPICLEN", strconv.Itoa(config.Limits.TopicLen))
	isupport.Add("UTF8MAPPING", casemappingName)

	err = isupport.RegenerateCachedReply()
	return
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
	err := server.connectionLimiter.AddClient(ipaddr, false)
	if err != nil {
		// too many connections from one client, tell the client and close the connection
		server.logger.Info("localconnect-ip", fmt.Sprintf("Client from %v rejected for connection limit", ipaddr))
		return true, "Too many clients from your network"
	}

	// check connection throttle
	err = server.connectionThrottler.AddClient(ipaddr)
	if err != nil {
		// too many connections too quickly from client, tell them and close the connection
		duration := server.connectionThrottler.BanDuration()
		if duration == 0 {
			return false, ""
		}
		server.dlines.AddIP(ipaddr, duration, server.connectionThrottler.BanMessage(), "Exceeded automated connection throttle", "auto.connection.throttler")

		// they're DLINE'd for 15 minutes or whatever, so we can reset the connection throttle now,
		// and once their temporary DLINE is finished they can fill up the throttler again
		server.connectionThrottler.ResetFor(ipaddr)

		// this might not show up properly on some clients, but our objective here is just to close it out before it has a load impact on us
		server.logger.Info(
			"localconnect-ip",
			fmt.Sprintf("Client from %v exceeded connection throttle, d-lining for %v", ipaddr, duration))
		return true, server.connectionThrottler.BanMessage()
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
func (server *Server) createListener(addr string, tlsConfig *tls.Config, isTor bool, bindMode os.FileMode) (*ListenerWrapper, error) {
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
		tlsConfig:  tlsConfig,
		isTor:      isTor,
		shouldStop: false,
	}

	var shouldStop bool

	// setup accept goroutine
	go func() {
		for {
			conn, err := listener.Accept()

			// synchronously access config data:
			wrapper.configMutex.Lock()
			shouldStop = wrapper.shouldStop
			tlsConfig = wrapper.tlsConfig
			isTor = wrapper.isTor
			wrapper.configMutex.Unlock()

			if err == nil {
				if tlsConfig != nil {
					conn = tls.Server(conn, tlsConfig)
				}
				newConn := clientConn{
					Conn:  conn,
					IsTLS: tlsConfig != nil,
					IsTor: isTor,
				}
				// hand off the connection
				go server.RunClient(newConn)
			}

			if shouldStop {
				listener.Close()
				return
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

	// client MUST send PASS if necessary, or authenticate with SASL if necessary,
	// before completing the other registration commands
	authOutcome := c.isAuthorized(server.Config())
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

	rb := NewResponseBuffer(session)
	nickAssigned := performNickChange(server, c, c, session, c.preregNick, rb)
	rb.Send(true)
	if !nickAssigned {
		c.preregNick = ""
		return
	}

	// check KLINEs
	isBanned, info := server.klines.CheckMasks(c.AllNickmasks()...)
	if isBanned {
		c.Quit(info.BanMessage(c.t("You are banned from this server (%s)")), nil)
		return true
	}

	if session.client != c {
		// reattached, bail out.
		// we'll play the reg burst later, on the new goroutine associated with
		// (thisSession, otherClient). This is to avoid having to transfer state
		// like nickname, hostname, etc. to show the correct values in the reg burst.
		return
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
	server.snomasks.Send(sno.LocalConnects, fmt.Sprintf("Client connected [%s] [u:%s] [h:%s] [ip:%s] [r:%s]", d.nick, d.username, c.RawHostname(), c.IPString(), d.realname))

	// send welcome text
	//NOTE(dan): we specifically use the NICK here instead of the nickmask
	// see http://modern.ircdocs.horse/#rplwelcome-001 for details on why we avoid using the nickmask
	session.Send(nil, server.name, RPL_WELCOME, d.nick, fmt.Sprintf(c.t("Welcome to the Internet Relay Network %s"), d.nick))
	session.Send(nil, server.name, RPL_YOURHOST, d.nick, fmt.Sprintf(c.t("Your host is %[1]s, running version %[2]s"), server.name, Ver))
	session.Send(nil, server.name, RPL_CREATED, d.nick, fmt.Sprintf(c.t("This server was created %s"), server.ctime.Format(time.RFC1123)))
	//TODO(dan): Look at adding last optional [<channel modes with a parameter>] parameter
	session.Send(nil, server.name, RPL_MYINFO, d.nick, server.name, Ver, supportedUserModesString, supportedChannelModesString)

	rb := NewResponseBuffer(session)
	server.RplISupport(c, rb)
	server.Lusers(c, rb)
	server.MOTD(c, rb)
	rb.Send(true)

	modestring := c.ModeString()
	if modestring != "+" {
		session.Send(nil, d.nickMask, RPL_UMODEIS, d.nick, modestring)
	}
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

	if target.certfp != "" && (client.HasMode(modes.Operator) || client == target) {
		rb.Add(nil, client.server.name, RPL_WHOISCERTFP, cnick, tnick, fmt.Sprintf(client.t("has client certificate fingerprint %s"), target.certfp))
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

	err = server.applyConfig(config, false)
	if err != nil {
		return fmt.Errorf("Error applying config changes: %s", err.Error())
	}

	return nil
}

func (server *Server) applyConfig(config *Config, initial bool) (err error) {
	if initial {
		server.configFilename = config.Filename
		server.name = config.Server.Name
		server.nameCasefolded = config.Server.nameCasefolded
	} else {
		// enforce configs that can't be changed after launch:
		currentLimits := server.Config().Limits
		if currentLimits.LineLen.Rest != config.Limits.LineLen.Rest {
			return fmt.Errorf("Maximum line length (linelen) cannot be changed after launching the server, rehash aborted")
		} else if server.name != config.Server.Name {
			return fmt.Errorf("Server name cannot be changed after launching the server, rehash aborted")
		} else if server.Config().Datastore.Path != config.Datastore.Path {
			return fmt.Errorf("Datastore path cannot be changed after launching the server, rehash aborted")
		}
	}

	// sanity checks complete, start modifying server state
	server.logger.Info("server", "Using config file", server.configFilename)
	oldConfig := server.Config()

	// first, reload config sections for functionality implemented in subpackages:

	err = server.connectionLimiter.ApplyConfig(config.Server.ConnectionLimiter)
	if err != nil {
		return err
	}

	err = server.connectionThrottler.ApplyConfig(config.Server.ConnectionThrottler)
	if err != nil {
		return err
	}

	tlConf := &config.Server.TorListeners
	server.torLimiter.Configure(tlConf.MaxConnections, tlConf.ThrottleDuration, tlConf.MaxConnectionsPerDuration)

	// reload logging config
	wasLoggingRawIO := !initial && server.logger.IsLoggingRawIO()
	err = server.logger.ApplyConfig(config.Logging)
	if err != nil {
		return err
	}
	nowLoggingRawIO := server.logger.IsLoggingRawIO()
	// notify existing clients if raw i/o logging was enabled by a rehash
	sendRawOutputNotice := !wasLoggingRawIO && nowLoggingRawIO

	// setup new and removed caps
	addedCaps := caps.NewSet()
	removedCaps := caps.NewSet()
	updatedCaps := caps.NewSet()

	// Translations
	server.logger.Debug("server", "Regenerating HELP indexes for new languages")
	server.helpIndexManager.GenerateIndices(config.languageManager)

	currentLanguageValue, _ := CapValues.Get(caps.Languages)
	newLanguageValue := config.languageManager.CapValue()
	if currentLanguageValue != newLanguageValue {
		updatedCaps.Add(caps.Languages)
		CapValues.Set(caps.Languages, newLanguageValue)
	}

	// SASL
	authPreviouslyEnabled := oldConfig != nil && oldConfig.Accounts.AuthenticationEnabled
	if config.Accounts.AuthenticationEnabled && (oldConfig == nil || !authPreviouslyEnabled) {
		// enabling SASL
		SupportedCapabilities.Enable(caps.SASL)
		CapValues.Set(caps.SASL, "PLAIN,EXTERNAL")
		addedCaps.Add(caps.SASL)
	} else if !config.Accounts.AuthenticationEnabled && (oldConfig == nil || authPreviouslyEnabled) {
		// disabling SASL
		SupportedCapabilities.Disable(caps.SASL)
		removedCaps.Add(caps.SASL)
	}

	nickReservationPreviouslyDisabled := oldConfig != nil && !oldConfig.Accounts.NickReservation.Enabled
	nickReservationNowEnabled := config.Accounts.NickReservation.Enabled
	if nickReservationPreviouslyDisabled && nickReservationNowEnabled {
		server.accounts.buildNickToAccountIndex()
	}

	hsPreviouslyDisabled := oldConfig != nil && !oldConfig.Accounts.VHosts.Enabled
	hsNowEnabled := config.Accounts.VHosts.Enabled
	if hsPreviouslyDisabled && hsNowEnabled {
		server.accounts.initVHostRequestQueue()
	}

	chanRegPreviouslyDisabled := oldConfig != nil && !oldConfig.Channels.Registration.Enabled
	chanRegNowEnabled := config.Channels.Registration.Enabled
	if chanRegPreviouslyDisabled && chanRegNowEnabled {
		server.channels.loadRegisteredChannels()
	}

	// MaxLine
	if config.Limits.LineLen.Rest != 512 {
		SupportedCapabilities.Enable(caps.MaxLine)
		value := fmt.Sprintf("%d", config.Limits.LineLen.Rest)
		CapValues.Set(caps.MaxLine, value)
	} else {
		SupportedCapabilities.Disable(caps.MaxLine)
	}

	// STS
	stsPreviouslyEnabled := oldConfig != nil && oldConfig.Server.STS.Enabled
	stsValue := config.Server.STS.Value()
	stsDisabledByRehash := false
	stsCurrentCapValue, _ := CapValues.Get(caps.STS)
	server.logger.Debug("server", "STS Vals", stsCurrentCapValue, stsValue, fmt.Sprintf("server[%v] config[%v]", stsPreviouslyEnabled, config.Server.STS.Enabled))
	if config.Server.STS.Enabled {
		// enabling STS
		SupportedCapabilities.Enable(caps.STS)
		if !stsPreviouslyEnabled {
			addedCaps.Add(caps.STS)
			CapValues.Set(caps.STS, stsValue)
		} else if stsValue != stsCurrentCapValue {
			// STS policy updated
			CapValues.Set(caps.STS, stsValue)
			updatedCaps.Add(caps.STS)
		}
	} else {
		// disabling STS
		SupportedCapabilities.Disable(caps.STS)
		if stsPreviouslyEnabled {
			removedCaps.Add(caps.STS)
			stsDisabledByRehash = true
		}
	}

	// resize history buffers as needed
	if oldConfig != nil {
		if oldConfig.History.ChannelLength != config.History.ChannelLength {
			for _, channel := range server.channels.Channels() {
				channel.history.Resize(config.History.ChannelLength)
			}
		}
		if oldConfig.History.ClientLength != config.History.ClientLength {
			for _, client := range server.clients.AllClients() {
				client.history.Resize(config.History.ClientLength)
			}
		}
	}

	// burst new and removed caps
	var capBurstSessions []*Session
	added := make(map[caps.Version]string)
	var removed string

	// updated caps get DEL'd and then NEW'd
	// so, we can just add updated ones to both removed and added lists here and they'll be correctly handled
	server.logger.Debug("server", "Updated Caps", updatedCaps.String(caps.Cap301, CapValues))
	addedCaps.Union(updatedCaps)
	removedCaps.Union(updatedCaps)

	if !addedCaps.Empty() || !removedCaps.Empty() {
		capBurstSessions = server.clients.AllWithCapsNotify()

		added[caps.Cap301] = addedCaps.String(caps.Cap301, CapValues)
		added[caps.Cap302] = addedCaps.String(caps.Cap302, CapValues)
		// removed never has values, so we leave it as Cap301
		removed = removedCaps.String(caps.Cap301, CapValues)
	}

	for _, sSession := range capBurstSessions {
		if stsDisabledByRehash {
			// remove STS policy
			//TODO(dan): this is an ugly hack. we can write this better.
			stsPolicy := "sts=duration=0"
			if !addedCaps.Empty() {
				added[caps.Cap302] = added[caps.Cap302] + " " + stsPolicy
			} else {
				addedCaps.Enable(caps.STS)
				added[caps.Cap302] = stsPolicy
			}
		}
		// DEL caps and then send NEW ones so that updated caps get removed/added correctly
		if !removedCaps.Empty() {
			sSession.Send(nil, server.name, "CAP", sSession.client.Nick(), "DEL", removed)
		}
		if !addedCaps.Empty() {
			sSession.Send(nil, server.name, "CAP", sSession.client.Nick(), "NEW", added[sSession.capVersion])
		}
	}

	// save a pointer to the new config
	server.SetConfig(config)

	server.logger.Info("server", "Using datastore", config.Datastore.Path)
	if initial {
		if err := server.loadDatastore(config); err != nil {
			return err
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

	return nil
}

func (server *Server) setupListeners(config *Config) (err error) {
	logListener := func(addr string, tlsconfig *tls.Config, isTor bool) {
		server.logger.Info("listeners",
			fmt.Sprintf("now listening on %s, tls=%t, tor=%t.", addr, (tlsconfig != nil), isTor),
		)
	}

	tlsListeners, err := config.TLSListeners()
	if err != nil {
		server.logger.Error("server", "failed to reload TLS certificates, aborting rehash", err.Error())
		return
	}

	isTorListener := func(listener string) bool {
		for _, torListener := range config.Server.TorListeners.Listeners {
			if listener == torListener {
				return true
			}
		}
		return false
	}

	// update or destroy all existing listeners
	for addr := range server.listeners {
		currentListener := server.listeners[addr]
		var stillConfigured bool
		for _, newaddr := range config.Server.Listen {
			if newaddr == addr {
				stillConfigured = true
				break
			}
		}

		// pass new config information to the listener, to be picked up after
		// its next Accept(). this is like sending over a buffered channel of
		// size 1, but where sending a second item overwrites the buffered item
		// instead of blocking.
		tlsConfig := tlsListeners[addr]
		isTor := isTorListener(addr)
		currentListener.configMutex.Lock()
		currentListener.shouldStop = !stillConfigured
		currentListener.tlsConfig = tlsConfig
		currentListener.isTor = isTor
		currentListener.configMutex.Unlock()

		if stillConfigured {
			logListener(addr, tlsConfig, isTor)
		} else {
			// tell the listener it should stop by interrupting its Accept() call:
			currentListener.listener.Close()
			delete(server.listeners, addr)
			server.logger.Info("listeners", fmt.Sprintf("stopped listening on %s.", addr))
		}
	}

	// create new listeners that were not previously configured
	for _, newaddr := range config.Server.Listen {
		_, exists := server.listeners[newaddr]
		if !exists {
			// make new listener
			isTor := isTorListener(newaddr)
			tlsConfig := tlsListeners[newaddr]
			listener, listenerErr := server.createListener(newaddr, tlsConfig, isTor, config.Server.UnixBindMode)
			if listenerErr != nil {
				server.logger.Error("server", "couldn't listen on", newaddr, listenerErr.Error())
				err = listenerErr
				continue
			}
			server.listeners[newaddr] = listener
			logListener(newaddr, tlsConfig, isTor)
		}
	}

	if len(tlsListeners) == 0 {
		server.logger.Warning("server", "You are not exposing an SSL/TLS listening port. You should expose at least one port (typically 6697) to accept TLS connections")
	}

	var usesStandardTLSPort bool
	for addr := range tlsListeners {
		if strings.HasSuffix(addr, ":6697") {
			usesStandardTLSPort = true
			break
		}
	}
	if 0 < len(tlsListeners) && !usesStandardTLSPort {
		server.logger.Warning("server", "Port 6697 is the standard TLS port for IRC. You should (also) expose port 6697 as a TLS port to ensure clients can connect securely")
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
