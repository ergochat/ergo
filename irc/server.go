// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"net"
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
	"github.com/oragono/oragono/irc/passwd"
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
	accountConfig              *AccountConfig
	accounts                   *AccountManager
	batches                    *BatchManager
	channelRegistrationEnabled bool
	channels                   *ChannelManager
	channelRegistry            *ChannelRegistry
	checkIdent                 bool
	clients                    *ClientManager
	configFilename             string
	configurableStateMutex     sync.RWMutex // tier 1; generic protection for server state modified by rehash()
	connectionLimiter          *connection_limits.Limiter
	connectionThrottler        *connection_limits.Throttler
	ctime                      time.Time
	defaultChannelModes        modes.Modes
	dlines                     *DLineManager
	loggingRawIO               bool
	isupport                   *isupport.List
	klines                     *KLineManager
	languages                  *languages.Manager
	limits                     Limits
	listeners                  map[string]*ListenerWrapper
	logger                     *logger.Manager
	MaxSendQBytes              uint64
	monitorManager             *MonitorManager
	motdLines                  []string
	name                       string
	nameCasefolded             string
	networkName                string
	operators                  map[string]Oper
	operclasses                map[string]OperClass
	password                   []byte
	passwords                  *passwd.SaltedManager
	recoverFromErrors          bool
	rehashMutex                sync.Mutex // tier 4
	rehashSignal               chan os.Signal
	proxyAllowedFrom           []string
	signals                    chan os.Signal
	snomasks                   *SnoManager
	store                      *buntdb.DB
	storeFilename              string
	stsEnabled                 bool
	webirc                     []webircConfig
	whoWas                     *WhoWasList
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
		batches:             NewBatchManager(),
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
func (server *Server) setISupport() {
	maxTargetsString := strconv.Itoa(maxTargets)

	server.configurableStateMutex.RLock()

	// add RPL_ISUPPORT tokens
	isupport := isupport.NewList()
	isupport.Add("AWAYLEN", strconv.Itoa(server.limits.AwayLen))
	isupport.Add("CASEMAPPING", "ascii")
	isupport.Add("CHANMODES", strings.Join([]string{modes.Modes{modes.BanMask, modes.ExceptMask, modes.InviteMask}.String(), "", modes.Modes{modes.UserLimit, modes.Key}.String(), modes.Modes{modes.InviteOnly, modes.Moderated, modes.NoOutside, modes.OpOnlyTopic, modes.ChanRoleplaying, modes.Secret}.String()}, ","))
	isupport.Add("CHANNELLEN", strconv.Itoa(server.limits.ChannelLen))
	isupport.Add("CHANTYPES", "#")
	isupport.Add("ELIST", "U")
	isupport.Add("EXCEPTS", "")
	isupport.Add("INVEX", "")
	isupport.Add("KICKLEN", strconv.Itoa(server.limits.KickLen))
	isupport.Add("MAXLIST", fmt.Sprintf("beI:%s", strconv.Itoa(server.limits.ChanListModes)))
	isupport.Add("MAXTARGETS", maxTargetsString)
	isupport.Add("MODES", "")
	isupport.Add("MONITOR", strconv.Itoa(server.limits.MonitorEntries))
	isupport.Add("NETWORK", server.networkName)
	isupport.Add("NICKLEN", strconv.Itoa(server.limits.NickLen))
	isupport.Add("PREFIX", "(qaohv)~&@%+")
	isupport.Add("RPCHAN", "E")
	isupport.Add("RPUSER", "E")
	isupport.Add("STATUSMSG", "~&@%+")
	isupport.Add("TARGMAX", fmt.Sprintf("NAMES:1,LIST:1,KICK:1,WHOIS:1,USERHOST:10,PRIVMSG:%s,TAGMSG:%s,NOTICE:%s,MONITOR:", maxTargetsString, maxTargetsString, maxTargetsString))
	isupport.Add("TOPICLEN", strconv.Itoa(server.limits.TopicLen))
	isupport.Add("UTF8MAPPING", casemappingName)

	// account registration
	if server.accountConfig.Registration.Enabled {
		// 'none' isn't shown in the REGCALLBACKS vars
		var enabledCallbacks []string
		for _, name := range server.accountConfig.Registration.EnabledCallbacks {
			if name != "*" {
				enabledCallbacks = append(enabledCallbacks, name)
			}
		}

		isupport.Add("REGCOMMANDS", "CREATE,VERIFY")
		isupport.Add("REGCALLBACKS", strings.Join(enabledCallbacks, ","))
		isupport.Add("REGCREDTYPES", "passphrase,certfp")
	}

	server.configurableStateMutex.RUnlock()

	isupport.RegenerateCachedReply()

	server.configurableStateMutex.Lock()
	server.isupport = isupport
	server.configurableStateMutex.Unlock()
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

// createListener starts the given listeners.
func (server *Server) createListener(addr string, tlsConfig *tls.Config) *ListenerWrapper {
	// make listener
	var listener net.Listener
	var err error
	addr = strings.TrimPrefix(addr, "unix:")
	if strings.HasPrefix(addr, "/") {
		// https://stackoverflow.com/a/34881585
		os.Remove(addr)
		listener, err = net.Listen("unix", addr)
	} else {
		listener, err = net.Listen("tcp", addr)
	}
	if err != nil {
		log.Fatal(server, "listen error: ", err)
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

	return &wrapper
}

// generateMessageID returns a network-unique message ID.
func (server *Server) generateMessageID() string {
	// we don't need the full like 30 chars since the unixnano below handles
	// most of our uniqueness requirements, so just truncate at 5
	lastbit := strconv.FormatInt(rand.Int63(), 36)
	if 5 < len(lastbit) {
		lastbit = lastbit[:4]
	}
	return fmt.Sprintf("%s%s", strconv.FormatInt(time.Now().UTC().UnixNano(), 36), lastbit)
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
	rb.Send()
	if !nickAssigned {
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

	// continue registration
	server.logger.Debug("localconnect", fmt.Sprintf("Client registered [%s] [u:%s] [r:%s]", c.nick, c.username, c.realname))
	server.snomasks.Send(sno.LocalConnects, fmt.Sprintf(ircfmt.Unescape("Client registered $c[grey][$r%s$c[grey]] [u:$r%s$c[grey]] [h:$r%s$c[grey]] [r:$r%s$c[grey]]"), c.nick, c.username, c.rawHostname, c.realname))
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
	rb.Send()

	c.Send(nil, c.nickMaskString, RPL_UMODEIS, c.nick, c.ModeString())
	if server.logger.IsLoggingRawIO() {
		c.Notice(c.t("This server is in debug mode and is logging all user I/O. If you do not wish for everything you send to be readable by the server owner(s), please disconnect."))
	}

	// if resumed, send fake channel joins
	if c.resumeDetails != nil {
		for _, name := range c.resumeDetails.SendFakeJoinsFor {
			channel := server.channels.Get(name)
			if channel == nil {
				continue
			}

			if c.capabilities.Has(caps.ExtendedJoin) {
				c.Send(nil, c.nickMaskString, "JOIN", channel.name, c.AccountName(), c.realname)
			} else {
				c.Send(nil, c.nickMaskString, "JOIN", channel.name)
			}
			// reuse the last rb
			channel.SendTopic(c, rb)
			channel.Names(c, rb)
			rb.Send()

			// construct and send fake modestring if necessary
			c.stateMutex.RLock()
			myModes := channel.members[c]
			c.stateMutex.RUnlock()
			if myModes == nil {
				continue
			}
			oldModes := myModes.String()
			if 0 < len(oldModes) {
				params := []string{channel.name, "+" + oldModes}
				for range oldModes {
					params = append(params, c.nick)
				}

				c.Send(nil, server.name, "MODE", params...)
			}
		}
	}
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

// wordWrap wraps the given text into a series of lines that don't exceed lineWidth characters.
func wordWrap(text string, lineWidth int) []string {
	var lines []string
	var cacheLine, cacheWord string

	for _, char := range text {
		if char == '\r' {
			continue
		} else if char == '\n' {
			cacheLine += cacheWord
			lines = append(lines, cacheLine)
			cacheWord = ""
			cacheLine = ""
		} else if (char == ' ' || char == '-') && len(cacheLine)+len(cacheWord)+1 < lineWidth {
			// natural word boundary
			cacheLine += cacheWord + string(char)
			cacheWord = ""
		} else if lineWidth <= len(cacheLine)+len(cacheWord)+1 {
			// time to wrap to next line
			if len(cacheLine) < (lineWidth / 2) {
				// this word takes up more than half a line... just split in the middle of the word
				cacheLine += cacheWord + string(char)
				cacheWord = ""
			} else {
				cacheWord += string(char)
			}
			lines = append(lines, cacheLine)
			cacheLine = ""
		} else {
			// normal character
			cacheWord += string(char)
		}
	}
	if 0 < len(cacheWord) {
		cacheLine += cacheWord
	}
	if 0 < len(cacheLine) {
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

// WhoisChannelsNames returns the common channel names between two users.
func (client *Client) WhoisChannelsNames(target *Client) []string {
	isMultiPrefix := target.capabilities.Has(caps.MultiPrefix)
	var chstrs []string
	for _, channel := range client.Channels() {
		// channel is secret and the target can't see it
		if !target.flags[modes.Operator] && channel.HasMode(modes.Secret) && !channel.hasClient(target) {
			continue
		}
		chstrs = append(chstrs, channel.ClientPrefixes(client, isMultiPrefix)+channel.name)
	}
	return chstrs
}

func (client *Client) getWhoisOf(target *Client, rb *ResponseBuffer) {
	target.stateMutex.RLock()
	defer target.stateMutex.RUnlock()

	rb.Add(nil, client.server.name, RPL_WHOISUSER, client.nick, target.nick, target.username, target.hostname, "*", target.realname)

	whoischannels := client.WhoisChannelsNames(target)
	if whoischannels != nil {
		rb.Add(nil, client.server.name, RPL_WHOISCHANNELS, client.nick, target.nick, strings.Join(whoischannels, " "))
	}
	if target.class != nil {
		rb.Add(nil, client.server.name, RPL_WHOISOPERATOR, client.nick, target.nick, target.whoisLine)
	}
	if client.flags[modes.Operator] || client == target {
		rb.Add(nil, client.server.name, RPL_WHOISACTUALLY, client.nick, target.nick, fmt.Sprintf("%s@%s", target.username, utils.LookupHostname(target.IPString())), target.IPString(), client.t("Actual user@host, Actual IP"))
	}
	if target.flags[modes.TLS] {
		rb.Add(nil, client.server.name, RPL_WHOISSECURE, client.nick, target.nick, client.t("is using a secure connection"))
	}
	if target.LoggedIntoAccount() {
		rb.Add(nil, client.server.name, RPL_WHOISACCOUNT, client.nick, client.AccountName(), client.t("is logged in as"))
	}
	if target.flags[modes.Bot] {
		rb.Add(nil, client.server.name, RPL_WHOISBOT, client.nick, target.nick, ircfmt.Unescape(fmt.Sprintf(client.t("is a $bBot$b on %s"), client.server.networkName)))
	}

	if 0 < len(target.languages) {
		params := []string{client.nick, target.nick}
		for _, str := range client.server.languages.Codes(target.languages) {
			params = append(params, str)
		}
		params = append(params, client.t("can speak these languages"))
		rb.Add(nil, client.server.name, RPL_WHOISLANGUAGE, params...)
	}

	if target.certfp != "" && (client.flags[modes.Operator] || client == target) {
		rb.Add(nil, client.server.name, RPL_WHOISCERTFP, client.nick, target.nick, fmt.Sprintf(client.t("has client certificate fingerprint %s"), target.certfp))
	}
	rb.Add(nil, client.server.name, RPL_WHOISIDLE, client.nick, target.nick, strconv.FormatUint(target.IdleSeconds(), 10), strconv.FormatInt(target.SignonTime(), 10), client.t("seconds idle, signon time"))
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
		if !client.flags[modes.Invisible] || friends[client] {
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

func (server *Server) applyConfig(config *Config, initial bool) error {
	if initial {
		server.ctime = time.Now()
		server.configFilename = config.Filename
	} else {
		// enforce configs that can't be changed after launch:
		if server.limits.LineLen.Tags != config.Limits.LineLen.Tags || server.limits.LineLen.Rest != config.Limits.LineLen.Rest {
			return fmt.Errorf("Maximum line length (linelen) cannot be changed after launching the server, rehash aborted")
		} else if server.name != config.Server.Name {
			return fmt.Errorf("Server name cannot be changed after launching the server, rehash aborted")
		} else if server.storeFilename != config.Datastore.Path {
			return fmt.Errorf("Datastore path cannot be changed after launching the server, rehash aborted")
		}
	}

	server.logger.Info("rehash", "Using config file", server.configFilename)

	casefoldedName, err := Casefold(config.Server.Name)
	if err != nil {
		return fmt.Errorf("Server name isn't valid [%s]: %s", config.Server.Name, err.Error())
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

	// TODO: support rehash of existing operator perms?

	// sanity checks complete, start modifying server state

	if initial {
		server.name = config.Server.Name
		server.nameCasefolded = casefoldedName
	}

	server.configurableStateMutex.Lock()
	server.networkName = config.Network.Name
	if config.Server.Password != "" {
		server.password = config.Server.PasswordBytes()
	} else {
		server.password = nil
	}
	// apply new WebIRC command restrictions
	server.webirc = config.Server.WebIRC
	// apply new PROXY command restrictions
	server.proxyAllowedFrom = config.Server.ProxyAllowedFrom
	server.recoverFromErrors = true
	if config.Debug.RecoverFromErrors != nil {
		server.recoverFromErrors = *config.Debug.RecoverFromErrors
	}
	server.configurableStateMutex.Unlock()

	err = server.connectionLimiter.ApplyConfig(config.Server.ConnectionLimiter)
	if err != nil {
		return err
	}

	err = server.connectionThrottler.ApplyConfig(config.Server.ConnectionThrottler)
	if err != nil {
		return err
	}

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
	oldAccountConfig := server.AccountConfig()
	authPreviouslyEnabled := oldAccountConfig != nil && oldAccountConfig.AuthenticationEnabled
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

	server.configurableStateMutex.Lock()
	server.accountConfig = &config.Accounts
	server.configurableStateMutex.Unlock()

	nickReservationPreviouslyDisabled := oldAccountConfig != nil && !oldAccountConfig.NickReservation.Enabled
	nickReservationNowEnabled := config.Accounts.NickReservation.Enabled
	if nickReservationPreviouslyDisabled && nickReservationNowEnabled {
		server.accounts.buildNickToAccountIndex()
	}

	// STS
	stsValue := config.Server.STS.Value()
	var stsDisabled bool
	stsCurrentCapValue, _ := CapValues.Get(caps.STS)
	server.logger.Debug("rehash", "STS Vals", stsCurrentCapValue, stsValue, fmt.Sprintf("server[%v] config[%v]", server.stsEnabled, config.Server.STS.Enabled))
	if config.Server.STS.Enabled && !server.stsEnabled {
		// enabling STS
		SupportedCapabilities.Enable(caps.STS)
		addedCaps.Add(caps.STS)
		CapValues.Set(caps.STS, stsValue)
	} else if !config.Server.STS.Enabled && server.stsEnabled {
		// disabling STS
		SupportedCapabilities.Disable(caps.STS)
		removedCaps.Add(caps.STS)
		stsDisabled = true
	} else if config.Server.STS.Enabled && server.stsEnabled && stsValue != stsCurrentCapValue {
		// STS policy updated
		CapValues.Set(caps.STS, stsValue)
		updatedCaps.Add(caps.STS)
	}
	server.stsEnabled = config.Server.STS.Enabled

	// burst new and removed caps
	var capBurstClients ClientSet
	added := make(map[caps.Version]string)
	var removed string

	// updated caps get DEL'd and then NEW'd
	// so, we can just add updated ones to both removed and added lists here and they'll be correctly handled
	server.logger.Debug("rehash", "Updated Caps", updatedCaps.String(caps.Cap301, CapValues), strconv.Itoa(updatedCaps.Count()))
	for _, capab := range updatedCaps.List() {
		addedCaps.Enable(capab)
		removedCaps.Enable(capab)
	}

	if 0 < addedCaps.Count() || 0 < removedCaps.Count() {
		capBurstClients = server.clients.AllWithCaps(caps.CapNotify)

		added[caps.Cap301] = addedCaps.String(caps.Cap301, CapValues)
		added[caps.Cap302] = addedCaps.String(caps.Cap302, CapValues)
		// removed never has values, so we leave it as Cap301
		removed = removedCaps.String(caps.Cap301, CapValues)
	}

	for sClient := range capBurstClients {
		if stsDisabled {
			// remove STS policy
			//TODO(dan): this is an ugly hack. we can write this better.
			stsPolicy := "sts=duration=0"
			if 0 < addedCaps.Count() {
				added[caps.Cap302] = added[caps.Cap302] + " " + stsPolicy
			} else {
				addedCaps.Enable(caps.STS)
				added[caps.Cap302] = stsPolicy
			}
		}
		// DEL caps and then send NEW ones so that updated caps get removed/added correctly
		if 0 < removedCaps.Count() {
			sClient.Send(nil, server.name, "CAP", sClient.nick, "DEL", removed)
		}
		if 0 < addedCaps.Count() {
			sClient.Send(nil, server.name, "CAP", sClient.nick, "NEW", added[sClient.capVersion])
		}
	}

	// set server options
	server.configurableStateMutex.Lock()
	lineLenConfig := LineLenLimits{
		Tags: config.Limits.LineLen.Tags,
		Rest: config.Limits.LineLen.Rest,
	}
	server.limits = Limits{
		AwayLen:        int(config.Limits.AwayLen),
		ChannelLen:     int(config.Limits.ChannelLen),
		KickLen:        int(config.Limits.KickLen),
		MonitorEntries: int(config.Limits.MonitorEntries),
		NickLen:        int(config.Limits.NickLen),
		TopicLen:       int(config.Limits.TopicLen),
		ChanListModes:  int(config.Limits.ChanListModes),
		LineLen:        lineLenConfig,
	}
	server.operclasses = *operclasses
	server.operators = opers
	server.checkIdent = config.Server.CheckIdent

	// registration
	server.channelRegistrationEnabled = config.Channels.Registration.Enabled

	server.defaultChannelModes = ParseDefaultChannelModes(config)
	server.configurableStateMutex.Unlock()

	// set new sendqueue size
	if config.Server.MaxSendQBytes != server.MaxSendQBytes {
		server.configurableStateMutex.Lock()
		server.MaxSendQBytes = config.Server.MaxSendQBytes
		server.configurableStateMutex.Unlock()

		// update on all clients
		for _, sClient := range server.clients.AllClients() {
			sClient.socket.MaxSendQBytes = config.Server.MaxSendQBytes
		}
	}

	// set RPL_ISUPPORT
	var newISupportReplies [][]string
	oldISupportList := server.isupport
	server.setISupport()
	if oldISupportList != nil {
		newISupportReplies = oldISupportList.GetDifference(server.isupport)
	}

	server.loadMOTD(config.Server.MOTD, config.Server.MOTDFormatting)

	// reload logging config
	err = server.logger.ApplyConfig(config.Logging)
	if err != nil {
		return err
	}
	nowLoggingRawIO := server.logger.IsLoggingRawIO()
	// notify clients if raw i/o logging was enabled by a rehash
	sendRawOutputNotice := !initial && !server.loggingRawIO && nowLoggingRawIO
	server.loggingRawIO = nowLoggingRawIO

	server.storeFilename = config.Datastore.Path
	server.logger.Info("rehash", "Using datastore", server.storeFilename)
	if initial {
		if err := server.loadDatastore(server.storeFilename); err != nil {
			return err
		}
	}

	// we are now open for business
	server.setupListeners(config)

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

	return nil
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

func (server *Server) loadDatastore(datastorePath string) error {
	// open the datastore and load server state for which it (rather than config)
	// is the source of truth

	db, err := OpenDatabase(datastorePath)
	if err == nil {
		server.store = db
	} else {
		return fmt.Errorf("Failed to open datastore: %s", err.Error())
	}

	// load *lines (from the datastores)
	server.logger.Debug("startup", "Loading D/Klines")
	server.loadDLines()
	server.loadKLines()

	// load password manager
	server.logger.Debug("startup", "Loading passwords")
	err = server.store.View(func(tx *buntdb.Tx) error {
		saltString, err := tx.Get(keySalt)
		if err != nil {
			return fmt.Errorf("Could not retrieve salt string: %s", err.Error())
		}

		salt, err := base64.StdEncoding.DecodeString(saltString)
		if err != nil {
			return err
		}

		pwm := passwd.NewSaltedManager(salt)
		server.passwords = &pwm
		return nil
	})
	if err != nil {
		return fmt.Errorf("Could not load salt: %s", err.Error())
	}

	server.channelRegistry = NewChannelRegistry(server)

	server.accounts = NewAccountManager(server)

	return nil
}

func (server *Server) setupListeners(config *Config) {
	logListener := func(addr string, tlsconfig *tls.Config) {
		server.logger.Info("listeners",
			fmt.Sprintf("now listening on %s, tls=%t.", addr, (tlsconfig != nil)),
		)
	}

	// update or destroy all existing listeners
	tlsListeners := config.TLSListeners()
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
			server.listeners[newaddr] = server.createListener(newaddr, tlsConfig)
			logListener(newaddr, tlsConfig)
		}
	}

	if len(tlsListeners) == 0 {
		server.logger.Warning("startup", "You are not exposing an SSL/TLS listening port. You should expose at least one port (typically 6697) to accept TLS connections")
	}

	var usesStandardTLSPort bool
	for addr := range config.TLSListeners() {
		if strings.Contains(addr, "6697") {
			usesStandardTLSPort = true
			break
		}
	}
	if 0 < len(tlsListeners) && !usesStandardTLSPort {
		server.logger.Warning("startup", "Port 6697 is the standard TLS port for IRC. You should (also) expose port 6697 as a TLS port to ensure clients can connect securely")
	}
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
	if target.flags[modes.Operator] || channel.hasClient(target) {
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

// ResumeDetails are the details that we use to resume connections.
type ResumeDetails struct {
	OldNick          string
	Timestamp        *time.Time
	SendFakeJoinsFor []string
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
