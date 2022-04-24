// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
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

	"github.com/ergochat/irc-go/ircfmt"
	"github.com/okzk/sdnotify"

	"github.com/ergochat/ergo/irc/caps"
	"github.com/ergochat/ergo/irc/connection_limits"
	"github.com/ergochat/ergo/irc/flatip"
	"github.com/ergochat/ergo/irc/flock"
	"github.com/ergochat/ergo/irc/history"
	"github.com/ergochat/ergo/irc/logger"
	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/mysql"
	"github.com/ergochat/ergo/irc/sno"
	"github.com/ergochat/ergo/irc/utils"
	"github.com/tidwall/buntdb"
)

const (
	alwaysOnMaintenanceInterval = 30 * time.Minute
)

var (
	// common error line to sub values into
	errorMsg = "ERROR :%s\r\n"

	// three final parameters of 004 RPL_MYINFO, enumerating our supported modes
	rplMyInfo1, rplMyInfo2, rplMyInfo3 = modes.RplMyInfo()

	// CHANMODES isupport token
	chanmodesToken = modes.ChanmodesToken()

	// whitelist of caps to serve on the STS-only listener. In particular,
	// never advertise SASL, to discourage people from sending their passwords:
	stsOnlyCaps = caps.NewSet(caps.STS, caps.MessageTags, caps.ServerTime, caps.Batch, caps.LabeledResponse, caps.EchoMessage, caps.Nope)

	// we only have standard channels for now. TODO: any updates to this
	// will also need to be reflected in CasefoldChannel
	chanTypes = "#"

	throttleMessage = "You have attempted to connect too many times within a short duration. Wait a while, and you will be able to connect."
)

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
	listeners         map[string]IRCListener
	logger            *logger.Manager
	monitorManager    MonitorManager
	name              string
	nameCasefolded    string
	rehashMutex       sync.Mutex // tier 4
	rehashSignal      chan os.Signal
	pprofServer       *http.Server
	exitSignals       chan os.Signal
	snomasks          SnoManager
	store             *buntdb.DB
	historyDB         mysql.MySQL
	torLimiter        connection_limits.TorLimiter
	whoWas            WhoWasList
	stats             Stats
	semaphores        ServerSemaphores
	flock             flock.Flocker
	defcon            uint32
}

// NewServer returns a new Oragono server.
func NewServer(config *Config, logger *logger.Manager) (*Server, error) {
	// initialize data structures
	server := &Server{
		ctime:        time.Now().UTC(),
		listeners:    make(map[string]IRCListener),
		logger:       logger,
		rehashSignal: make(chan os.Signal, 1),
		exitSignals:  make(chan os.Signal, len(utils.ServerExitSignals)),
		defcon:       5,
	}

	server.clients.Initialize()
	server.semaphores.Initialize()
	server.whoWas.Initialize(config.Limits.WhowasEntries)
	server.monitorManager.Initialize()
	server.snomasks.Initialize()

	if err := server.applyConfig(config); err != nil {
		return nil, err
	}

	// Attempt to clean up when receiving these signals.
	signal.Notify(server.exitSignals, utils.ServerExitSignals...)
	signal.Notify(server.rehashSignal, syscall.SIGHUP)

	time.AfterFunc(alwaysOnMaintenanceInterval, server.periodicAlwaysOnMaintenance)

	return server, nil
}

// Shutdown shuts down the server.
func (server *Server) Shutdown() {
	sdnotify.Stopping()
	server.logger.Info("server", "Stopping server")

	//TODO(dan): Make sure we disallow new nicks
	for _, client := range server.clients.AllClients() {
		client.Notice("Server is shutting down")
	}

	// flush data associated with always-on clients:
	server.performAlwaysOnMaintenance(false, true)

	if err := server.store.Close(); err != nil {
		server.logger.Error("shutdown", fmt.Sprintln("Could not close datastore:", err))
	}

	server.historyDB.Close()
	server.logger.Info("server", fmt.Sprintf("%s exiting", Ver))
}

// Run starts the server.
func (server *Server) Run() {
	defer server.Shutdown()

	for {
		select {
		case <-server.exitSignals:
			return
		case <-server.rehashSignal:
			server.logger.Info("server", "Rehashing due to SIGHUP")
			go server.rehash()
		}
	}
}

func (server *Server) checkBans(config *Config, ipaddr net.IP, checkScripts bool) (banned bool, requireSASL bool, message string) {
	// #671: do not enforce bans against loopback, as a failsafe
	// note that this function is not used for Tor connections (checkTorLimits is used instead)
	if ipaddr.IsLoopback() {
		return
	}

	if server.Defcon() == 1 {
		if !utils.IPInNets(ipaddr, server.Config().Server.secureNets) {
			return true, false, "New connections to this server are temporarily restricted"
		}
	}

	flat := flatip.FromNetIP(ipaddr)

	// check DLINEs
	isBanned, info := server.dlines.CheckIP(flat)
	if isBanned {
		if info.RequireSASL {
			server.logger.Info("connect-ip", "Requiring SASL from client due to d-line", ipaddr.String())
			return false, true, info.BanMessage("You must authenticate with SASL to connect from this IP (%s)")
		} else {
			server.logger.Info("connect-ip", "Client rejected by d-line", ipaddr.String())
			return true, false, info.BanMessage("You are banned from this server (%s)")
		}
	}

	// check connection limits
	err := server.connectionLimiter.AddClient(flat)
	if err == connection_limits.ErrLimitExceeded {
		// too many connections from one client, tell the client and close the connection
		server.logger.Info("connect-ip", "Client rejected for connection limit", ipaddr.String())
		return true, false, "Too many clients from your network"
	} else if err == connection_limits.ErrThrottleExceeded {
		server.logger.Info("connect-ip", "Client exceeded connection throttle", ipaddr.String())
		return true, false, throttleMessage
	} else if err != nil {
		server.logger.Warning("internal", "unexpected ban result", err.Error())
	}

	if checkScripts && config.Server.IPCheckScript.Enabled && !config.Server.IPCheckScript.ExemptSASL {
		output, err := CheckIPBan(server.semaphores.IPCheckScript, config.Server.IPCheckScript, ipaddr)
		if err != nil {
			server.logger.Error("internal", "couldn't check IP ban script", ipaddr.String(), err.Error())
			return false, false, ""
		}
		// TODO: currently no way to cache IPAccepted
		if (output.Result == IPBanned || output.Result == IPRequireSASL) && output.CacheSeconds != 0 {
			network, err := flatip.ParseToNormalizedNet(output.CacheNet)
			if err != nil {
				server.logger.Error("internal", "invalid dline net from IP ban script", ipaddr.String(), output.CacheNet)
			} else {
				dlineDuration := time.Duration(output.CacheSeconds) * time.Second
				err := server.dlines.AddNetwork(network, dlineDuration, output.Result == IPRequireSASL, output.BanMessage, "", "")
				if err != nil {
					server.logger.Error("internal", "couldn't set dline from IP ban script", ipaddr.String(), err.Error())
				}
			}
		}
		if output.Result == IPBanned {
			// XXX roll back IP connection/throttling addition for the IP
			server.connectionLimiter.RemoveClient(flat)
			server.logger.Info("connect-ip", "Rejected client due to ip-check-script", ipaddr.String())
			return true, false, output.BanMessage
		} else if output.Result == IPRequireSASL {
			server.logger.Info("connect-ip", "Requiring SASL from client due to ip-check-script", ipaddr.String())
			return false, true, output.BanMessage
		}
	}

	return false, false, ""
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

func (server *Server) periodicAlwaysOnMaintenance() {
	defer func() {
		// reschedule whether or not there was a panic
		time.AfterFunc(alwaysOnMaintenanceInterval, server.periodicAlwaysOnMaintenance)
	}()

	defer server.HandlePanic()

	server.logger.Info("accounts", "Performing periodic always-on client checks")
	server.performAlwaysOnMaintenance(true, true)
}

func (server *Server) performAlwaysOnMaintenance(checkExpiration, flushTimestamps bool) {
	config := server.Config()
	for _, client := range server.clients.AllClients() {
		if checkExpiration && client.IsExpiredAlwaysOn(config) {
			// TODO save the channels list, use it for autojoin if/when they return?
			server.logger.Info("accounts", "Expiring always-on client", client.AccountName())
			client.destroy(nil)
			continue
		}

		if flushTimestamps && client.shouldFlushTimestamps() {
			account := client.Account()
			server.accounts.saveLastSeen(account, client.copyLastSeen())
			server.accounts.saveReadMarkers(account, client.copyReadMarkers())
		}
	}
}

// handles server.ip-check-script.exempt-sasl:
// run the ip check script at the end of the handshake, only for anonymous connections
func (server *Server) checkBanScriptExemptSASL(config *Config, session *Session) (outcome AuthOutcome) {
	// TODO add caching for this; see related code in (*server).checkBans;
	// we should probably just put an LRU around this instead of using the DLINE system
	ipaddr := session.IP()
	output, err := CheckIPBan(server.semaphores.IPCheckScript, config.Server.IPCheckScript, ipaddr)
	if err != nil {
		server.logger.Error("internal", "couldn't check IP ban script", ipaddr.String(), err.Error())
		return authSuccess
	}
	if output.Result == IPBanned || output.Result == IPRequireSASL {
		server.logger.Info("connect-ip", "Rejecting unauthenticated client due to ip-check-script", ipaddr.String())
		if output.BanMessage != "" {
			session.client.requireSASLMessage = output.BanMessage
		}
		return authFailSaslRequired
	}
	return authSuccess
}

func (server *Server) tryRegister(c *Client, session *Session) (exiting bool) {
	// XXX PROXY or WEBIRC MUST be sent as the first line of the session;
	// if we are here at all that means we have the final value of the IP
	if session.rawHostname == "" {
		session.client.lookupHostname(session, false)
	}

	// try to complete registration normally
	// XXX(#1057) username can be filled in by an ident query without the client
	// having sent USER: check for both username and realname to ensure they did
	if c.preregNick == "" || c.username == "" || c.realname == "" || session.capState == caps.NegotiatingState {
		return
	}

	if c.isSTSOnly {
		server.playSTSBurst(session)
		return true
	}

	// client MUST send PASS if necessary, or authenticate with SASL if necessary,
	// before completing the other registration commands
	config := server.Config()
	authOutcome := c.isAuthorized(server, config, session, c.requireSASL)
	if authOutcome == authSuccess && c.account == "" &&
		config.Server.IPCheckScript.Enabled && config.Server.IPCheckScript.ExemptSASL {
		authOutcome = server.checkBanScriptExemptSASL(config, session)
	}
	var quitMessage string
	switch authOutcome {
	case authFailPass:
		quitMessage = c.t("Password incorrect")
		c.Send(nil, server.name, ERR_PASSWDMISMATCH, "*", quitMessage)
	case authFailSaslRequired, authFailTorSaslRequired:
		quitMessage = c.requireSASLMessage
		if quitMessage == "" {
			quitMessage = c.t("You must log in with SASL to join this server")
		}
		c.Send(nil, c.server.name, "FAIL", "*", "ACCOUNT_REQUIRED", quitMessage)
	}
	if authOutcome != authSuccess {
		c.Quit(quitMessage, nil)
		return true
	}
	c.requireSASLMessage = ""

	rb := NewResponseBuffer(session)
	nickError := performNickChange(server, c, c, session, c.preregNick, rb)
	rb.Send(true)
	if nickError == errInsecureReattach {
		c.Quit(c.t("You can't mix secure and insecure connections to this account"), nil)
		return true
	} else if nickError != nil {
		c.preregNick = ""
		return false
	}

	if session.client != c {
		// reattached, bail out.
		// we'll play the reg burst later, on the new goroutine associated with
		// (thisSession, otherClient). This is to avoid having to transfer state
		// like nickname, hostname, etc. to show the correct values in the reg burst.
		return false
	}

	// Apply default user modes (without updating the invisible counter)
	// The number of invisible users will be updated by server.stats.Register
	// if we're using default user mode +i.
	for _, defaultMode := range config.Accounts.defaultUserModes {
		c.SetMode(defaultMode, true)
	}

	// count new user in statistics (before checking KLINEs, see #1303)
	server.stats.Register(c.HasMode(modes.Invisible))

	// check KLINEs (#671: ignore KLINEs for loopback connections)
	if !session.IP().IsLoopback() || session.isTor {
		isBanned, info := server.klines.CheckMasks(c.AllNickmasks()...)
		if isBanned {
			c.Quit(info.BanMessage(c.t("You are banned from this server (%s)")), nil)
			return true
		}
	}

	server.playRegistrationBurst(session)
	return false
}

func (server *Server) playSTSBurst(session *Session) {
	nick := utils.SafeErrorParam(session.client.preregNick)
	session.Send(nil, server.name, RPL_WELCOME, nick, fmt.Sprintf("Welcome to the Internet Relay Network %s", nick))
	session.Send(nil, server.name, RPL_YOURHOST, nick, fmt.Sprintf("Your host is %[1]s, running version %[2]s", server.name, "ergo"))
	session.Send(nil, server.name, RPL_CREATED, nick, fmt.Sprintf("This server was created %s", time.Time{}.Format(time.RFC1123)))
	session.Send(nil, server.name, RPL_MYINFO, nick, server.name, "ergo", "o", "o", "o")
	session.Send(nil, server.name, RPL_ISUPPORT, nick, "CASEMAPPING=ascii", "are supported by this server")
	session.Send(nil, server.name, ERR_NOMOTD, nick, "MOTD is unavailable")
	for _, line := range server.Config().Server.STS.bannerLines {
		session.Send(nil, server.name, "NOTICE", nick, line)
	}
}

func (server *Server) playRegistrationBurst(session *Session) {
	c := session.client
	// continue registration
	d := c.Details()
	server.logger.Info("connect", fmt.Sprintf("Client connected [%s] [u:%s] [r:%s]", d.nick, d.username, d.realname))
	server.snomasks.Send(sno.LocalConnects, fmt.Sprintf("Client connected [%s] [u:%s] [h:%s] [ip:%s] [r:%s]", d.nick, d.username, session.rawHostname, session.IP().String(), d.realname))
	if d.account != "" {
		server.sendLoginSnomask(d.nickMask, d.accountName)
	}

	// send welcome text
	//NOTE(dan): we specifically use the NICK here instead of the nickmask
	// see http://modern.ircdocs.horse/#rplwelcome-001 for details on why we avoid using the nickmask
	config := server.Config()
	session.Send(nil, server.name, RPL_WELCOME, d.nick, fmt.Sprintf(c.t("Welcome to the %s IRC Network %s"), config.Network.Name, d.nick))
	session.Send(nil, server.name, RPL_YOURHOST, d.nick, fmt.Sprintf(c.t("Your host is %[1]s, running version %[2]s"), server.name, Ver))
	session.Send(nil, server.name, RPL_CREATED, d.nick, fmt.Sprintf(c.t("This server was created %s"), server.ctime.Format(time.RFC1123)))
	session.Send(nil, server.name, RPL_MYINFO, d.nick, server.name, Ver, rplMyInfo1, rplMyInfo2, rplMyInfo3)

	rb := NewResponseBuffer(session)
	server.RplISupport(c, rb)
	server.Lusers(c, rb)
	server.MOTD(c, rb)
	rb.Send(true)

	modestring := c.ModeString()
	if modestring != "+" {
		session.Send(nil, server.name, RPL_UMODEIS, d.nick, modestring)
	}

	c.attemptAutoOper(session)

	if server.logger.IsLoggingRawIO() {
		session.Send(nil, c.server.name, "NOTICE", d.nick, c.t("This server is in debug mode and is logging all user I/O. If you do not wish for everything you send to be readable by the server owner(s), please disconnect."))
	}
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
	config := server.Config()
	var stats StatsValues
	var numChannels int
	if !config.Server.SuppressLusers || client.HasRoleCapabs("ban") {
		stats = server.stats.GetValues()
		numChannels = server.channels.Len()
	}

	rb.Add(nil, server.name, RPL_LUSERCLIENT, nick, fmt.Sprintf(client.t("There are %[1]d users and %[2]d invisible on %[3]d server(s)"), stats.Total-stats.Invisible, stats.Invisible, 1))
	rb.Add(nil, server.name, RPL_LUSEROP, nick, strconv.Itoa(stats.Operators), client.t("IRC Operators online"))
	rb.Add(nil, server.name, RPL_LUSERUNKNOWN, nick, strconv.Itoa(stats.Unknown), client.t("unregistered connections"))
	rb.Add(nil, server.name, RPL_LUSERCHANNELS, nick, strconv.Itoa(numChannels), client.t("channels formed"))
	rb.Add(nil, server.name, RPL_LUSERME, nick, fmt.Sprintf(client.t("I have %[1]d clients and %[2]d servers"), stats.Total, 0))
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

func (client *Client) whoisChannelsNames(target *Client, multiPrefix bool, hasPrivs bool) []string {
	var chstrs []string
	targetInvis := target.HasMode(modes.Invisible)
	for _, channel := range target.Channels() {
		if !hasPrivs && (targetInvis || channel.flags.HasMode(modes.Secret)) && !channel.hasClient(client) {
			// client can't see *this* channel membership
			continue
		}
		chstrs = append(chstrs, channel.ClientPrefixes(target, multiPrefix)+channel.name)
	}
	return chstrs
}

func (client *Client) getWhoisOf(target *Client, hasPrivs bool, rb *ResponseBuffer) {
	oper := client.Oper()
	cnick := client.Nick()
	targetInfo := target.Details()
	rb.Add(nil, client.server.name, RPL_WHOISUSER, cnick, targetInfo.nick, targetInfo.username, targetInfo.hostname, "*", targetInfo.realname)
	tnick := targetInfo.nick

	whoischannels := client.whoisChannelsNames(target, rb.session.capabilities.Has(caps.MultiPrefix), oper.HasRoleCapab("sajoin"))
	if whoischannels != nil {
		for _, line := range utils.BuildTokenLines(maxLastArgLength, whoischannels, " ") {
			rb.Add(nil, client.server.name, RPL_WHOISCHANNELS, cnick, tnick, line)
		}
	}
	if target.HasMode(modes.Operator) && operStatusVisible(client, target, oper != nil) {
		tOper := target.Oper()
		if tOper != nil {
			rb.Add(nil, client.server.name, RPL_WHOISOPERATOR, cnick, tnick, tOper.WhoisLine)
		}
	}
	if client == target || oper.HasRoleCapab("ban") {
		ip, hostname := target.getWhoisActually()
		rb.Add(nil, client.server.name, RPL_WHOISACTUALLY, cnick, tnick, fmt.Sprintf("%s@%s", targetInfo.username, hostname), utils.IPStringToHostname(ip.String()), client.t("Actual user@host, Actual IP"))
	}
	if client == target || oper.HasRoleCapab("samode") {
		rb.Add(nil, client.server.name, RPL_WHOISMODES, cnick, tnick, fmt.Sprintf(client.t("is using modes +%s"), target.modes.String()))
	}
	if target.HasMode(modes.TLS) {
		rb.Add(nil, client.server.name, RPL_WHOISSECURE, cnick, tnick, client.t("is using a secure connection"))
	}
	if targetInfo.accountName != "*" {
		rb.Add(nil, client.server.name, RPL_WHOISACCOUNT, cnick, tnick, targetInfo.accountName, client.t("is logged in as"))
	}
	if target.HasMode(modes.Bot) {
		rb.Add(nil, client.server.name, RPL_WHOISBOT, cnick, tnick, fmt.Sprintf(ircfmt.Unescape(client.t("is a $bBot$b on %s")), client.server.Config().Network.Name))
	}

	if client == target || oper.HasRoleCapab("ban") {
		for _, session := range target.Sessions() {
			if session.certfp != "" {
				rb.Add(nil, client.server.name, RPL_WHOISCERTFP, cnick, tnick, fmt.Sprintf(client.t("has client certificate fingerprint %s"), session.certfp))
			}
		}
	}
	rb.Add(nil, client.server.name, RPL_WHOISIDLE, cnick, tnick, strconv.FormatUint(target.IdleSeconds(), 10), strconv.FormatInt(target.SignonTime(), 10), client.t("seconds idle, signon time"))
	if away, awayMessage := target.Away(); away {
		rb.Add(nil, client.server.name, RPL_AWAY, cnick, tnick, awayMessage)
	}
}

// rehash reloads the config and applies the changes from the config file.
func (server *Server) rehash() error {
	// #1570; this needs its own panic handling because it can be invoked via SIGHUP
	defer server.HandlePanic()

	server.logger.Info("server", "Attempting rehash")

	// only let one REHASH go on at a time
	server.rehashMutex.Lock()
	defer server.rehashMutex.Unlock()

	sdnotify.Reloading()
	defer sdnotify.Ready()

	config, err := LoadConfig(server.configFilename)
	if err != nil {
		server.logger.Error("server", "failed to load config file", err.Error())
		return err
	}

	err = server.applyConfig(config)
	if err != nil {
		server.logger.Error("server", "Failed to rehash", err.Error())
		return err
	}

	server.logger.Info("server", "Rehash completed successfully")
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
		globalUtf8EnforcementSetting = config.Server.EnforceUtf8
		MaxLineLen = config.Server.MaxLineLen
	} else {
		// enforce configs that can't be changed after launch:
		if server.name != config.Server.Name {
			return fmt.Errorf("Server name cannot be changed after launching the server, rehash aborted")
		} else if oldConfig.Datastore.Path != config.Datastore.Path {
			return fmt.Errorf("Datastore path cannot be changed after launching the server, rehash aborted")
		} else if globalCasemappingSetting != config.Server.Casemapping {
			return fmt.Errorf("Casemapping cannot be changed after launching the server, rehash aborted")
		} else if globalUtf8EnforcementSetting != config.Server.EnforceUtf8 {
			return fmt.Errorf("UTF-8 enforcement cannot be changed after launching the server, rehash aborted")
		} else if oldConfig.Accounts.Multiclient.AlwaysOn != config.Accounts.Multiclient.AlwaysOn {
			return fmt.Errorf("Default always-on setting cannot be changed after launching the server, rehash aborted")
		} else if oldConfig.Server.Relaymsg.Enabled != config.Server.Relaymsg.Enabled {
			return fmt.Errorf("Cannot enable or disable relaying after launching the server, rehash aborted")
		} else if oldConfig.Server.Relaymsg.Separators != config.Server.Relaymsg.Separators {
			return fmt.Errorf("Cannot change relaying separators after launching the server, rehash aborted")
		} else if oldConfig.Server.IPCheckScript.MaxConcurrency != config.Server.IPCheckScript.MaxConcurrency ||
			oldConfig.Accounts.AuthScript.MaxConcurrency != config.Accounts.AuthScript.MaxConcurrency {
			return fmt.Errorf("Cannot change max-concurrency for scripts after launching the server, rehash aborted")
		} else if oldConfig.Server.OverrideServicesHostname != config.Server.OverrideServicesHostname {
			return fmt.Errorf("Cannot change override-services-hostname after launching the server, rehash aborted")
		} else if !oldConfig.Datastore.MySQL.Enabled && config.Datastore.MySQL.Enabled {
			return fmt.Errorf("Cannot enable MySQL after launching the server, rehash aborted")
		} else if oldConfig.Server.MaxLineLen != config.Server.MaxLineLen {
			return fmt.Errorf("Cannot change max-line-len after launching the server, rehash aborted")
		}
	}

	server.logger.Info("server", "Using config file", server.configFilename)

	if initial {
		if config.LockFile != "" {
			server.flock, err = flock.TryAcquireFlock(config.LockFile)
			if err != nil {
				return fmt.Errorf("failed to acquire flock on %s: %w",
					config.LockFile, err)
			}
		}
		// the lock is never released until quit; we need to save a pointer
		// to the (*flock.Flock) object so it doesn't get GC'ed, which would
		// close the file and surrender the lock
	}

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

	if initial {
		maxIPConc := int(config.Server.IPCheckScript.MaxConcurrency)
		if maxIPConc != 0 {
			server.semaphores.IPCheckScript = utils.NewSemaphore(maxIPConc)
		}
		maxAuthConc := int(config.Accounts.AuthScript.MaxConcurrency)
		if maxAuthConc != 0 {
			server.semaphores.AuthScript = utils.NewSemaphore(maxAuthConc)
		}

		if err := overrideServicePrefixes(config.Server.OverrideServicesHostname); err != nil {
			return err
		}
	}

	if oldConfig != nil {
		// if certain features were enabled by rehash, we need to load the corresponding data
		// from the store
		if !oldConfig.Accounts.NickReservation.Enabled {
			server.accounts.buildNickToAccountIndex(config)
		}
		if !oldConfig.Channels.Registration.Enabled {
			server.channels.loadRegisteredChannels(config)
		}
		// resize history buffers as needed
		if config.historyChangedFrom(oldConfig) {
			for _, channel := range server.channels.Channels() {
				channel.resizeHistory(config)
			}
			for _, client := range server.clients.AllClients() {
				client.resizeHistory(config)
			}
		}
		if oldConfig.Accounts.Registration.Throttling != config.Accounts.Registration.Throttling {
			server.accounts.resetRegisterThrottle(config)
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

	// now that the datastore is initialized, we can load the cloak secret from it
	// XXX this modifies config after the initial load, which is naughty,
	// but there's no data race because we haven't done SetConfig yet
	config.Server.Cloaks.SetSecret(LoadCloakSecret(server.store))

	// activate the new config
	server.SetConfig(config)

	// load [dk]-lines, registered users and channels, etc.
	if initial {
		if err := server.loadFromDatastore(config); err != nil {
			return err
		}
	}

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

	server.setupPprofListener(config)

	// set RPL_ISUPPORT
	var newISupportReplies [][]string
	if oldConfig != nil {
		newISupportReplies = oldConfig.Server.isupport.GetDifference(&config.Server.isupport)
	}

	if len(config.Server.ProxyAllowedFrom) != 0 {
		server.logger.Info("server", "Proxied IPs will be accepted from", strings.Join(config.Server.ProxyAllowedFrom, ", "))
	}

	// we are now ready to receive connections:
	err = server.setupListeners(config)

	if initial && err == nil {
		server.logger.Info("server", "Server running")
		sdnotify.Ready()
	}

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

	// send other config warnings
	if config.Accounts.RequireSasl.Enabled && config.Accounts.Registration.Enabled {
		server.logger.Warning("server", "Warning: although require-sasl is enabled, users can still register accounts. If your server is not intended to be public, you must set accounts.registration.enabled to false.")
	}

	return err
}

func (server *Server) setupPprofListener(config *Config) {
	pprofListener := config.Debug.PprofListener
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
		return nil
	} else {
		return fmt.Errorf("Failed to open datastore: %s", err.Error())
	}
}

func (server *Server) loadFromDatastore(config *Config) (err error) {
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
	logListener := func(addr string, config utils.ListenerConfig) {
		server.logger.Info("listeners",
			fmt.Sprintf("now listening on %s, tls=%t, proxy=%t, tor=%t, websocket=%t.", addr, (config.TLSConfig != nil), config.RequireProxy, config.Tor, config.WebSocket),
		)
	}

	// update or destroy all existing listeners
	for addr := range server.listeners {
		currentListener := server.listeners[addr]
		newConfig, stillConfigured := config.Server.trueListeners[addr]

		if stillConfigured {
			if reloadErr := currentListener.Reload(newConfig); reloadErr == nil {
				logListener(addr, newConfig)
			} else {
				// stop the listener; we will attempt to replace it below
				currentListener.Stop()
				delete(server.listeners, addr)
			}
		} else {
			currentListener.Stop()
			delete(server.listeners, addr)
			server.logger.Info("listeners", fmt.Sprintf("stopped listening on %s.", addr))
		}
	}

	publicPlaintextListener := ""
	// create new listeners that were not previously configured,
	// or that couldn't be reloaded above:
	for newAddr, newConfig := range config.Server.trueListeners {
		if strings.HasPrefix(newAddr, ":") && !newConfig.Tor && !newConfig.STSOnly && newConfig.TLSConfig == nil {
			publicPlaintextListener = newAddr
		}
		_, exists := server.listeners[newAddr]
		if !exists {
			// make a new listener
			newListener, newErr := NewListener(server, newAddr, newConfig, config.Server.UnixBindMode)
			if newErr == nil {
				server.listeners[newAddr] = newListener
				logListener(newAddr, newConfig)
			} else {
				server.logger.Error("server", "couldn't listen on", newAddr, newErr.Error())
				err = newErr
			}
		}
	}

	if publicPlaintextListener != "" {
		server.logger.Warning("listeners", fmt.Sprintf("Warning: your server is configured with public plaintext listener %s. Consider disabling it for improved security and privacy.", publicPlaintextListener))
	}

	return
}

// Gets the abstract sequence from which we're going to query history;
// we may already know the channel we're querying, or we may have
// to look it up via a string query. This function is responsible for
// privilege checking.
// XXX: call this with providedChannel==nil and query=="" to get a sequence
// suitable for ListCorrespondents (i.e., this function is still used to
// decide whether the ringbuf or mysql is authoritative about the client's
// message history).
func (server *Server) GetHistorySequence(providedChannel *Channel, client *Client, query string) (channel *Channel, sequence history.Sequence, err error) {
	config := server.Config()
	// 4 cases: {persistent, ephemeral} x {normal, conversation}
	// with ephemeral history, target is implicit in the choice of `hist`,
	// and correspondent is "" if we're retrieving a channel or *, and the correspondent's name
	// if we're retrieving a DM conversation ("query buffer"). with persistent history,
	// target is always nonempty, and correspondent is either empty or nonempty as before.
	var status HistoryStatus
	var target, correspondent string
	var hist *history.Buffer
	restriction := HistoryCutoffNone
	channel = providedChannel
	if channel == nil {
		if strings.HasPrefix(query, "#") {
			channel = server.channels.Get(query)
			if channel == nil {
				return
			}
		}
	}
	var joinTimeCutoff time.Time
	if channel != nil {
		if present, cutoff := channel.joinTimeCutoff(client); present {
			joinTimeCutoff = cutoff
		} else {
			err = errInsufficientPrivs
			return
		}
		status, target, restriction = channel.historyStatus(config)
		switch status {
		case HistoryEphemeral:
			hist = &channel.history
		case HistoryPersistent:
			// already set `target`
		default:
			return
		}
	} else {
		status, target = client.historyStatus(config)
		if query != "" {
			correspondent, err = CasefoldName(query)
			if err != nil {
				return
			}
		}
		switch status {
		case HistoryEphemeral:
			hist = &client.history
		case HistoryPersistent:
			// already set `target`, and `correspondent` if necessary
		default:
			return
		}
	}

	var cutoff time.Time
	if config.History.Restrictions.ExpireTime != 0 {
		cutoff = time.Now().UTC().Add(-time.Duration(config.History.Restrictions.ExpireTime))
	}
	// #836: registration date cutoff is always enforced for DMs
	// either way, take the later of the two cutoffs
	if restriction == HistoryCutoffRegistrationTime || channel == nil {
		regCutoff := client.historyCutoff()
		if regCutoff.After(cutoff) {
			cutoff = regCutoff
		}
	} else if restriction == HistoryCutoffJoinTime {
		if joinTimeCutoff.After(cutoff) {
			cutoff = joinTimeCutoff
		}
	}

	// #836 again: grace period is never applied to DMs
	if !cutoff.IsZero() && channel != nil && restriction != HistoryCutoffJoinTime {
		cutoff = cutoff.Add(-time.Duration(config.History.Restrictions.GracePeriod))
	}

	if hist != nil {
		sequence = hist.MakeSequence(correspondent, cutoff)
	} else if target != "" {
		sequence = server.historyDB.MakeSequence(target, correspondent, cutoff)
	}
	return
}

func (server *Server) ForgetHistory(accountName string) {
	// sanity check
	if accountName == "*" {
		return
	}

	config := server.Config()
	if !config.History.Enabled {
		return
	}

	if cfAccount, err := CasefoldName(accountName); err == nil {
		server.historyDB.Forget(cfAccount)
	}

	persistent := config.History.Persistent
	if persistent.Enabled && persistent.UnregisteredChannels && persistent.RegisteredChannels == PersistentMandatory && persistent.DirectMessages == PersistentMandatory {
		return
	}

	predicate := func(item *history.Item) bool { return item.AccountName == accountName }

	for _, channel := range server.channels.Channels() {
		channel.history.Delete(predicate)
	}

	for _, client := range server.clients.AllClients() {
		client.history.Delete(predicate)
	}
}

// deletes a message. target is a hint about what buffer it's in (not required for
// persistent history, where all the msgids are indexed together). if accountName
// is anything other than "*", it must match the recorded AccountName of the message
func (server *Server) DeleteMessage(target, msgid, accountName string) (err error) {
	config := server.Config()
	var hist *history.Buffer

	if target != "" {
		if target[0] == '#' {
			channel := server.channels.Get(target)
			if channel != nil {
				if status, _, _ := channel.historyStatus(config); status == HistoryEphemeral {
					hist = &channel.history
				}
			}
		} else {
			client := server.clients.Get(target)
			if client != nil {
				if status, _ := client.historyStatus(config); status == HistoryEphemeral {
					hist = &client.history
				}
			}
		}
	}

	if hist == nil {
		err = server.historyDB.DeleteMsgid(msgid, accountName)
	} else {
		count := hist.Delete(func(item *history.Item) bool {
			return item.Message.Msgid == msgid && (accountName == "*" || item.AccountName == accountName)
		})
		if count == 0 {
			err = errNoop
		}
	}

	return
}

func (server *Server) UnfoldName(cfname string) (name string) {
	if strings.HasPrefix(cfname, "#") {
		return server.channels.UnfoldName(cfname)
	}
	return server.clients.UnfoldNick(cfname)
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
		if len(channel.Members()) > matcher.MaxClients {
			return false
		}
	}

	return true
}

var (
	infoString1 = strings.Split(`
      __ __  ______ ___  ______ ___ 
   __/ // /_/ ____/ __ \/ ____/ __ \
  /_  // __/ __/ / /_/ / / __/ / / /
 /_  // __/ /___/ _, _/ /_/ / /_/ / 
  /_//_/ /_____/_/ |_|\____/\____/  

         https://ergo.chat/
  https://github.com/ergochat/ergo  
`, "\n")[1:]  // XXX: cut off initial blank line
	infoString2 = strings.Split(`    Daniel Oakley,          DanielOaks,    <daniel@danieloaks.net>
    Shivaram Lingamneni,    slingamn,      <slingamn@cs.stanford.edu>
`, "\n")
	infoString3 = strings.Split(`    Jeremy Latt,            jlatt
    Edmund Huber,           edmund-huber
`, "\n")
)
