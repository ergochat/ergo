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

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/oragono/oragono/irc/caps"
	"github.com/oragono/oragono/irc/connection_limits"
	"github.com/oragono/oragono/irc/isupport"
	"github.com/oragono/oragono/irc/languages"
	"github.com/oragono/oragono/irc/logger"
	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/sno"
	"github.com/oragono/oragono/irc/utils"
	"github.com/tidwall/buntdb"
)

var (
	// common error line to sub values into
	errorMsg, _ = (&[]ircmsg.IrcMessage{ircmsg.MakeMessage(nil, "", "ERROR", "%s ")}[0]).Line()

	// common error responses
	couldNotParseIPMsg, _ = (&[]ircmsg.IrcMessage{ircmsg.MakeMessage(nil, "", "ERROR", "Unable to parse your IP address")}[0]).Line()

	// supportedUserModesString acts as a cache for when we introduce users
	supportedUserModesString = modes.SupportedUserModes.String()
	// supportedChannelModesString acts as a cache for when we introduce users
	supportedChannelModesString = modes.SupportedChannelModes.String()

	// SupportedCapabilities are the caps we advertise.
	// MaxLine, SASL and STS are set during server startup.
	SupportedCapabilities = caps.NewSet(caps.AccountTag, caps.AccountNotify, caps.AwayNotify, caps.Batch, caps.CapNotify, caps.ChgHost, caps.EchoMessage, caps.ExtendedJoin, caps.InviteNotify, caps.LabeledResponse, caps.Languages, caps.MessageTags, caps.MultiPrefix, caps.Rename, caps.Resume, caps.ServerTime, caps.UserhostInNames)

	// CapValues are the actual values we advertise to v3.2 clients.
	// actual values are set during server startup.
	CapValues = caps.NewValues()
)

// ListenerWrapper wraps a listener so it can be safely reconfigured or stopped
type ListenerWrapper struct {
	listener   net.Listener
	tlsConfig  *tls.Config
	shouldStop bool
	// protects atomic update of tlsConfig and shouldStop:
	configMutex sync.Mutex // tier 1
}

// Server is the main Oragono server.
type Server struct {
	accounts               *AccountManager
	channels               *ChannelManager
	channelRegistry        *ChannelRegistry
	clients                *ClientManager
	config                 *Config
	configFilename         string
	configurableStateMutex sync.RWMutex // tier 1; generic protection for server state modified by rehash()
	connectionLimiter      *connection_limits.Limiter
	connectionThrottler    *connection_limits.Throttler
	ctime                  time.Time
	dlines                 *DLineManager
	isupport               *isupport.List
	klines                 *KLineManager
	languages              *languages.Manager
	listeners              map[string]*ListenerWrapper
	logger                 *logger.Manager
	monitorManager         *MonitorManager
	motdLines              []string
	name                   string
	nameCasefolded         string
	rehashMutex            sync.Mutex // tier 4
	rehashSignal           chan os.Signal
	pprofServer            *http.Server
	signals                chan os.Signal
	snomasks               *SnoManager
	store                  *buntdb.DB
	whoWas                 *WhoWasList
	stats                  *Stats
	semaphores             *ServerSemaphores
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
func NewServer(config *Config, logger *logger.Manager) (*Server, error) {
	// initialize data structures
	server := &Server{
		channels:            NewChannelManager(),
		clients:             NewClientManager(),
		connectionLimiter:   connection_limits.NewLimiter(),
		connectionThrottler: connection_limits.NewThrottler(),
		languages:           languages.NewManager(config.Languages.Default, config.Languages.Data),
		listeners:           make(map[string]*ListenerWrapper),
		logger:              logger,
		monitorManager:      NewMonitorManager(),
		rehashSignal:        make(chan os.Signal, 1),
		signals:             make(chan os.Signal, len(ServerExitSignals)),
		snomasks:            NewSnoManager(),
		whoWas:              NewWhoWasList(config.Limits.WhowasEntries),
		stats:               NewStats(),
		semaphores:          NewServerSemaphores(),
	}

	if err := server.applyConfig(config, true); err != nil {
		return nil, err
	}

	// generate help info
	if err := GenerateHelpIndices(server.languages); err != nil {
		return nil, err
	}

	// Attempt to clean up when receiving these signals.
	signal.Notify(server.signals, ServerExitSignals...)
	signal.Notify(server.rehashSignal, syscall.SIGHUP)

	return server, nil
}

// setISupport sets up our RPL_ISUPPORT reply.
func (server *Server) setISupport() (err error) {
	maxTargetsString := strconv.Itoa(maxTargets)

	config := server.Config()

	// add RPL_ISUPPORT tokens
	isupport := isupport.NewList()
	isupport.Add("AWAYLEN", strconv.Itoa(config.Limits.AwayLen))
	isupport.Add("CASEMAPPING", "ascii")
	isupport.Add("CHANMODES", strings.Join([]string{modes.Modes{modes.BanMask, modes.ExceptMask, modes.InviteMask}.String(), "", modes.Modes{modes.UserLimit, modes.Key}.String(), modes.Modes{modes.InviteOnly, modes.Moderated, modes.NoOutside, modes.OpOnlyTopic, modes.ChanRoleplaying, modes.Secret}.String()}, ","))
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

	// account registration
	if config.Accounts.Registration.Enabled {
		// 'none' isn't shown in the REGCALLBACKS vars
		var enabledCallbacks []string
		for _, name := range server.config.Accounts.Registration.EnabledCallbacks {
			if name != "*" {
				enabledCallbacks = append(enabledCallbacks, name)
			}
		}

		isupport.Add("ACCCOMMANDS", "CREATE,VERIFY")
		isupport.Add("REGCALLBACKS", strings.Join(enabledCallbacks, ","))
		isupport.Add("REGCREDTYPES", "passphrase,certfp")
	}

	err = isupport.RegenerateCachedReply()
	if err != nil {
		return
	}

	server.configurableStateMutex.Lock()
	server.isupport = isupport
	server.configurableStateMutex.Unlock()
	return
}

func loadChannelList(channel *Channel, list string, maskMode modes.Mode) {
	if list == "" {
		return
	}
	channel.lists[maskMode].AddAll(strings.Split(list, " "))
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
				server.logger.Info("rehash", "Rehashing due to SIGHUP")
				err := server.rehash()
				if err != nil {
					server.logger.Error("rehash", fmt.Sprintln("Failed to rehash:", err.Error()))
				}
			}()
		}
	}
}

func (server *Server) acceptClient(conn clientConn) {
	// check IP address
	ipaddr := utils.AddrToIP(conn.Conn.RemoteAddr())
	if ipaddr != nil {
		isBanned, banMsg := server.checkBans(ipaddr)
		if isBanned {
			// this might not show up properly on some clients, but our objective here is just to close the connection out before it has a load impact on us
			conn.Conn.Write([]byte(fmt.Sprintf(errorMsg, banMsg)))
			conn.Conn.Close()
			return
		}
	}

	server.logger.Debug("localconnect-ip", fmt.Sprintf("Client connecting from %v", ipaddr))
	// prolly don't need to alert snomasks on this, only on connection reg

	NewClient(server, conn.Conn, conn.IsTLS)
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
		length := &IPRestrictTime{
			Duration: duration,
			Expires:  time.Now().Add(duration),
		}
		server.dlines.AddIP(ipaddr, length, server.connectionThrottler.BanMessage(), "Exceeded automated connection throttle", "auto.connection.throttler")

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

//
// IRC protocol listeners
//

// createListener starts a given listener.
func (server *Server) createListener(addr string, tlsConfig *tls.Config, bindMode os.FileMode) (*ListenerWrapper, error) {
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
		shouldStop: false,
	}

	var shouldStop bool

	// setup accept goroutine
	go func() {
		for {
			conn, err := listener.Accept()

			// synchronously access config data:
			// whether TLS is enabled and whether we should stop listening
			wrapper.configMutex.Lock()
			shouldStop = wrapper.shouldStop
			tlsConfig = wrapper.tlsConfig
			wrapper.configMutex.Unlock()

			if err == nil {
				if tlsConfig != nil {
					conn = tls.Server(conn, tlsConfig)
				}
				newConn := clientConn{
					Conn:  conn,
					IsTLS: tlsConfig != nil,
				}
				// hand off the connection
				go server.acceptClient(newConn)
			}

			if shouldStop {
				listener.Close()
				return
			}
		}
	}()

	return &wrapper, nil
}

// generateMessageID returns a network-unique message ID.
func (server *Server) generateMessageID() string {
	return utils.GenerateSecretToken()
}

//
// server functionality
//

func (server *Server) tryRegister(c *Client) {
	if c.Registered() {
		return
	}

	preregNick := c.PreregNick()
	if preregNick == "" || !c.HasUsername() || c.capState == caps.NegotiatingState {
		return
	}

	// client MUST send PASS (or AUTHENTICATE, if skip-server-password is set)
	// before completing the other registration commands
	if !c.Authorized() {
		c.Quit(c.t("Bad password"))
		c.destroy(false)
		return
	}

	rb := NewResponseBuffer(c)
	nickAssigned := performNickChange(server, c, c, preregNick, rb)
	rb.Send(true)
	if !nickAssigned {
		c.SetPreregNick("")
		return
	}

	// check KLINEs
	isBanned, info := server.klines.CheckMasks(c.AllNickmasks()...)
	if isBanned {
		reason := info.Reason
		if info.Time != nil {
			reason += fmt.Sprintf(" [%s]", info.Time.Duration.String())
		}
		c.Quit(fmt.Sprintf(c.t("You are banned from this server (%s)"), reason))
		c.destroy(false)
		return
	}

	// count new user in statistics
	server.stats.ChangeTotal(1)

	// continue registration
	server.logger.Debug("localconnect", fmt.Sprintf("Client connected [%s] [u:%s] [r:%s]", c.nick, c.username, c.realname))
	server.snomasks.Send(sno.LocalConnects, fmt.Sprintf("Client connected [%s] [u:%s] [h:%s] [ip:%s] [r:%s]", c.nick, c.username, c.rawHostname, c.IPString(), c.realname))

	// "register"; this includes the initial phase of session resumption
	c.Register()

	// send welcome text
	//NOTE(dan): we specifically use the NICK here instead of the nickmask
	// see http://modern.ircdocs.horse/#rplwelcome-001 for details on why we avoid using the nickmask
	c.Send(nil, server.name, RPL_WELCOME, c.nick, fmt.Sprintf(c.t("Welcome to the Internet Relay Network %s"), c.nick))
	c.Send(nil, server.name, RPL_YOURHOST, c.nick, fmt.Sprintf(c.t("Your host is %[1]s, running version %[2]s"), server.name, Ver))
	c.Send(nil, server.name, RPL_CREATED, c.nick, fmt.Sprintf(c.t("This server was created %s"), server.ctime.Format(time.RFC1123)))
	//TODO(dan): Look at adding last optional [<channel modes with a parameter>] parameter
	c.Send(nil, server.name, RPL_MYINFO, c.nick, server.name, Ver, supportedUserModesString, supportedChannelModesString)

	rb = NewResponseBuffer(c)
	c.RplISupport(rb)
	server.MOTD(c, rb)
	rb.Send(true)

	modestring := c.ModeString()
	if modestring != "+" {
		c.Send(nil, c.nickMaskString, RPL_UMODEIS, c.nick, c.ModeString())
	}
	if server.logger.IsLoggingRawIO() {
		c.Notice(c.t("This server is in debug mode and is logging all user I/O. If you do not wish for everything you send to be readable by the server owner(s), please disconnect."))
	}

	// if resumed, send fake channel joins
	c.tryResumeChannels()
}

// t returns the translated version of the given string, based on the languages configured by the client.
func (client *Client) t(originalString string) string {
	// grab this mutex to protect client.languages
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()

	return client.server.languages.Translate(client.languages, originalString)
}

// MOTD serves the Message of the Day.
func (server *Server) MOTD(client *Client, rb *ResponseBuffer) {
	server.configurableStateMutex.RLock()
	motdLines := server.motdLines
	server.configurableStateMutex.RUnlock()

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
func (client *Client) WhoisChannelsNames(target *Client) []string {
	isMultiPrefix := client.capabilities.Has(caps.MultiPrefix)
	var chstrs []string
	for _, channel := range target.Channels() {
		// channel is secret and the target can't see it
		if !client.HasMode(modes.Operator) {
			if (target.HasMode(modes.Invisible) || channel.flags.HasMode(modes.Secret)) && !channel.hasClient(client) {
				continue
			}
		}
		chstrs = append(chstrs, channel.ClientPrefixes(target, isMultiPrefix)+channel.name)
	}
	return chstrs
}

func (client *Client) getWhoisOf(target *Client, rb *ResponseBuffer) {
	cnick := client.Nick()
	targetInfo := target.WhoWas()
	rb.Add(nil, client.server.name, RPL_WHOISUSER, cnick, targetInfo.nickname, targetInfo.username, targetInfo.hostname, "*", targetInfo.realname)
	tnick := targetInfo.nickname

	whoischannels := client.WhoisChannelsNames(target)
	if whoischannels != nil {
		rb.Add(nil, client.server.name, RPL_WHOISCHANNELS, cnick, tnick, strings.Join(whoischannels, " "))
	}
	tOper := target.Oper()
	if tOper != nil {
		rb.Add(nil, client.server.name, RPL_WHOISOPERATOR, cnick, tnick, tOper.WhoisLine)
	}
	if client.HasMode(modes.Operator) || client == target {
		rb.Add(nil, client.server.name, RPL_WHOISACTUALLY, cnick, tnick, fmt.Sprintf("%s@%s", target.username, utils.LookupHostname(target.IPString())), target.IPString(), client.t("Actual user@host, Actual IP"))
	}
	if target.HasMode(modes.TLS) {
		rb.Add(nil, client.server.name, RPL_WHOISSECURE, cnick, tnick, client.t("is using a secure connection"))
	}
	taccount := target.AccountName()
	if taccount != "*" {
		rb.Add(nil, client.server.name, RPL_WHOISACCOUNT, cnick, tnick, taccount, client.t("is logged in as"))
	}
	if target.HasMode(modes.Bot) {
		rb.Add(nil, client.server.name, RPL_WHOISBOT, cnick, tnick, ircfmt.Unescape(fmt.Sprintf(client.t("is a $bBot$b on %s"), client.server.Config().Network.Name)))
	}

	if 0 < len(target.languages) {
		params := []string{cnick, tnick}
		for _, str := range client.server.languages.Codes(target.languages) {
			params = append(params, str)
		}
		params = append(params, client.t("can speak these languages"))
		rb.Add(nil, client.server.name, RPL_WHOISLANGUAGE, params...)
	}

	if target.certfp != "" && (client.HasMode(modes.Operator) || client == target) {
		rb.Add(nil, client.server.name, RPL_WHOISCERTFP, cnick, tnick, fmt.Sprintf(client.t("has client certificate fingerprint %s"), target.certfp))
	}
	rb.Add(nil, client.server.name, RPL_WHOISIDLE, cnick, tnick, strconv.FormatUint(target.IdleSeconds(), 10), strconv.FormatInt(target.SignonTime(), 10), client.t("seconds idle, signon time"))
}

// rplWhoReply returns the WHO reply between one user and another channel/user.
// <channel> <user> <host> <server> <nick> ( "H" / "G" ) ["*"] [ ( "@" / "+" ) ]
// :<hopcount> <real name>
func (target *Client) rplWhoReply(channel *Channel, client *Client, rb *ResponseBuffer) {
	channelName := "*"
	flags := ""

	if client.HasMode(modes.Away) {
		flags = "G"
	} else {
		flags = "H"
	}
	if client.HasMode(modes.Operator) {
		flags += "*"
	}

	if channel != nil {
		flags += channel.ClientPrefixes(client, target.capabilities.Has(caps.MultiPrefix))
		channelName = channel.name
	}
	rb.Add(nil, target.server.name, RPL_WHOREPLY, target.nick, channelName, client.Username(), client.Hostname(), client.server.name, client.Nick(), flags, strconv.Itoa(client.hops)+" "+client.Realname())
}

func whoChannel(client *Client, channel *Channel, friends ClientSet, rb *ResponseBuffer) {
	for _, member := range channel.Members() {
		if !client.HasMode(modes.Invisible) || friends[client] {
			client.rplWhoReply(channel, member, rb)
		}
	}
}

// rehash reloads the config and applies the changes from the config file.
func (server *Server) rehash() error {
	server.logger.Debug("rehash", "Starting rehash")

	// only let one REHASH go on at a time
	server.rehashMutex.Lock()
	defer server.rehashMutex.Unlock()

	server.logger.Debug("rehash", "Got rehash lock")

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
		server.ctime = time.Now()
		server.configFilename = config.Filename
		server.name = config.Server.Name
		server.nameCasefolded = config.Server.nameCasefolded
	} else {
		// enforce configs that can't be changed after launch:
		currentLimits := server.Limits()
		if currentLimits.LineLen.Tags != config.Limits.LineLen.Tags || currentLimits.LineLen.Rest != config.Limits.LineLen.Rest {
			return fmt.Errorf("Maximum line length (linelen) cannot be changed after launching the server, rehash aborted")
		} else if server.name != config.Server.Name {
			return fmt.Errorf("Server name cannot be changed after launching the server, rehash aborted")
		} else if server.config.Datastore.Path != config.Datastore.Path {
			return fmt.Errorf("Datastore path cannot be changed after launching the server, rehash aborted")
		}
	}

	// sanity checks complete, start modifying server state
	server.logger.Info("rehash", "Using config file", server.configFilename)
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
	currentLanguageValue, _ := CapValues.Get(caps.Languages)

	langCodes := []string{strconv.Itoa(len(config.Languages.Data) + 1), "en"}
	for _, info := range config.Languages.Data {
		if info.Incomplete {
			langCodes = append(langCodes, "~"+info.Code)
		} else {
			langCodes = append(langCodes, info.Code)
		}
	}
	newLanguageValue := strings.Join(langCodes, ",")
	server.logger.Debug("rehash", "Languages:", newLanguageValue)

	if currentLanguageValue != newLanguageValue {
		updatedCaps.Add(caps.Languages)
		CapValues.Set(caps.Languages, newLanguageValue)
	}

	lm := languages.NewManager(config.Languages.Default, config.Languages.Data)

	server.logger.Debug("rehash", "Regenerating HELP indexes for new languages")
	GenerateHelpIndices(lm)

	server.languages = lm

	// SASL
	authPreviouslyEnabled := oldConfig != nil && oldConfig.Accounts.AuthenticationEnabled
	if config.Accounts.AuthenticationEnabled && !authPreviouslyEnabled {
		// enabling SASL
		SupportedCapabilities.Enable(caps.SASL)
		CapValues.Set(caps.SASL, "PLAIN,EXTERNAL")
		addedCaps.Add(caps.SASL)
	} else if !config.Accounts.AuthenticationEnabled && authPreviouslyEnabled {
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

	// STS
	stsPreviouslyEnabled := oldConfig != nil && oldConfig.Server.STS.Enabled
	stsValue := config.Server.STS.Value()
	stsDisabledByRehash := false
	stsCurrentCapValue, _ := CapValues.Get(caps.STS)
	server.logger.Debug("rehash", "STS Vals", stsCurrentCapValue, stsValue, fmt.Sprintf("server[%v] config[%v]", stsPreviouslyEnabled, config.Server.STS.Enabled))
	if config.Server.STS.Enabled && !stsPreviouslyEnabled {
		// enabling STS
		SupportedCapabilities.Enable(caps.STS)
		addedCaps.Add(caps.STS)
		CapValues.Set(caps.STS, stsValue)
	} else if !config.Server.STS.Enabled && stsPreviouslyEnabled {
		// disabling STS
		SupportedCapabilities.Disable(caps.STS)
		removedCaps.Add(caps.STS)
		stsDisabledByRehash = true
	} else if config.Server.STS.Enabled && stsPreviouslyEnabled && stsValue != stsCurrentCapValue {
		// STS policy updated
		CapValues.Set(caps.STS, stsValue)
		updatedCaps.Add(caps.STS)
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
	var capBurstClients ClientSet
	added := make(map[caps.Version]string)
	var removed string

	// updated caps get DEL'd and then NEW'd
	// so, we can just add updated ones to both removed and added lists here and they'll be correctly handled
	server.logger.Debug("rehash", "Updated Caps", updatedCaps.String(caps.Cap301, CapValues))
	addedCaps.Union(updatedCaps)
	removedCaps.Union(updatedCaps)

	if !addedCaps.Empty() || !removedCaps.Empty() {
		capBurstClients = server.clients.AllWithCaps(caps.CapNotify)

		added[caps.Cap301] = addedCaps.String(caps.Cap301, CapValues)
		added[caps.Cap302] = addedCaps.String(caps.Cap302, CapValues)
		// removed never has values, so we leave it as Cap301
		removed = removedCaps.String(caps.Cap301, CapValues)
	}

	for sClient := range capBurstClients {
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
			sClient.Send(nil, server.name, "CAP", sClient.nick, "DEL", removed)
		}
		if !addedCaps.Empty() {
			sClient.Send(nil, server.name, "CAP", sClient.nick, "NEW", added[sClient.capVersion])
		}
	}

	server.loadMOTD(config.Server.MOTD, config.Server.MOTDFormatting)

	// save a pointer to the new config
	server.configurableStateMutex.Lock()
	server.config = config
	server.configurableStateMutex.Unlock()

	server.logger.Info("rehash", "Using datastore", config.Datastore.Path)
	if initial {
		if err := server.loadDatastore(config); err != nil {
			return err
		}
	}

	server.setupPprofListener(config)

	// set RPL_ISUPPORT
	var newISupportReplies [][]string
	oldISupportList := server.ISupport()
	err = server.setISupport()
	if err != nil {
		return err
	}
	if oldISupportList != nil {
		newISupportReplies = oldISupportList.GetDifference(server.ISupport())
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
			server.logger.Info("rehash", "Stopping pprof listener", server.pprofServer.Addr)
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
				server.logger.Error("rehash", fmt.Sprintf("pprof listener failed: %v", err))
			}
		}()
		server.pprofServer = &ps
		server.logger.Info("rehash", "Started pprof listener", server.pprofServer.Addr)
	}
}

func (server *Server) loadMOTD(motdPath string, useFormatting bool) error {
	server.logger.Info("rehash", "Using MOTD", motdPath)
	motdLines := make([]string, 0)
	if motdPath != "" {
		file, err := os.Open(motdPath)
		if err == nil {
			defer file.Close()

			reader := bufio.NewReader(file)
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				line = strings.TrimRight(line, "\r\n")

				if useFormatting {
					line = ircfmt.Unescape(line)
				}

				// "- " is the required prefix for MOTD, we just add it here to make
				// bursting it out to clients easier
				line = fmt.Sprintf("- %s", line)

				motdLines = append(motdLines, line)
			}
		} else {
			return err
		}
	}

	server.configurableStateMutex.Lock()
	server.motdLines = motdLines
	server.configurableStateMutex.Unlock()
	return nil
}

func (server *Server) loadDatastore(config *Config) error {
	// open the datastore and load server state for which it (rather than config)
	// is the source of truth

	_, err := os.Stat(config.Datastore.Path)
	if os.IsNotExist(err) {
		server.logger.Warning("rehash", "database does not exist, creating it", config.Datastore.Path)
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
	server.logger.Debug("rehash", "Loading D/Klines")
	server.loadDLines()
	server.loadKLines()

	server.channelRegistry = NewChannelRegistry(server)

	server.accounts = NewAccountManager(server)

	return nil
}

func (server *Server) setupListeners(config *Config) (err error) {
	logListener := func(addr string, tlsconfig *tls.Config) {
		server.logger.Info("listeners",
			fmt.Sprintf("now listening on %s, tls=%t.", addr, (tlsconfig != nil)),
		)
	}

	tlsListeners, err := config.TLSListeners()
	if err != nil {
		server.logger.Error("rehash", "failed to reload TLS certificates, aborting rehash", err.Error())
		return
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
		currentListener.configMutex.Lock()
		currentListener.shouldStop = !stillConfigured
		currentListener.tlsConfig = tlsListeners[addr]
		currentListener.configMutex.Unlock()

		if stillConfigured {
			logListener(addr, currentListener.tlsConfig)
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
			tlsConfig := tlsListeners[newaddr]
			listener, listenerErr := server.createListener(newaddr, tlsConfig, config.Server.UnixBindMode)
			if listenerErr != nil {
				server.logger.Error("rehash", "couldn't listen on", newaddr, listenerErr.Error())
				err = listenerErr
				continue
			}
			server.listeners[newaddr] = listener
			logListener(newaddr, tlsConfig)
		}
	}

	if len(tlsListeners) == 0 {
		server.logger.Warning("rehash", "You are not exposing an SSL/TLS listening port. You should expose at least one port (typically 6697) to accept TLS connections")
	}

	var usesStandardTLSPort bool
	for addr := range tlsListeners {
		if strings.HasSuffix(addr, ":6697") {
			usesStandardTLSPort = true
			break
		}
	}
	if 0 < len(tlsListeners) && !usesStandardTLSPort {
		server.logger.Warning("rehash", "Port 6697 is the standard TLS port for IRC. You should (also) expose port 6697 as a TLS port to ensure clients can connect securely")
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
