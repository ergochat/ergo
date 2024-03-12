// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"crypto/x509"
	"fmt"
	"maps"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ident "github.com/ergochat/go-ident"
	"github.com/ergochat/irc-go/ircfmt"
	"github.com/ergochat/irc-go/ircmsg"
	"github.com/ergochat/irc-go/ircreader"
	"github.com/ergochat/irc-go/ircutils"
	"github.com/xdg-go/scram"

	"github.com/ergochat/ergo/irc/caps"
	"github.com/ergochat/ergo/irc/connection_limits"
	"github.com/ergochat/ergo/irc/flatip"
	"github.com/ergochat/ergo/irc/history"
	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/oauth2"
	"github.com/ergochat/ergo/irc/sno"
	"github.com/ergochat/ergo/irc/utils"
)

const (
	// maximum IRC line length, not including tags
	DefaultMaxLineLen = 512

	// IdentTimeout is how long before our ident (username) check times out.
	IdentTimeout         = time.Second + 500*time.Millisecond
	IRCv3TimestampFormat = utils.IRCv3TimestampFormat
	// limit the number of device IDs a client can use, as a DoS mitigation
	maxDeviceIDsPerClient = 64
	// maximum total read markers that can be stored
	// (writeback of read markers is controlled by lastSeen logic)
	maxReadMarkers = 256
)

const (
	// RegisterTimeout is how long clients have to register before we disconnect them
	RegisterTimeout = time.Minute
	// DefaultIdleTimeout is how long without traffic before we send the client a PING
	DefaultIdleTimeout = time.Minute + 30*time.Second
	// For Tor clients, we send a PING at least every 30 seconds, as a workaround for this bug
	// (single-onion circuits will close unless the client sends data once every 60 seconds):
	// https://bugs.torproject.org/29665
	TorIdleTimeout = time.Second * 30
	// This is how long a client gets without sending any message, including the PONG to our
	// PING, before we disconnect them:
	DefaultTotalTimeout = 2*time.Minute + 30*time.Second

	// round off the ping interval by this much, see below:
	PingCoalesceThreshold = time.Second
)

var (
	MaxLineLen = DefaultMaxLineLen
)

// Client is an IRC client.
type Client struct {
	account            string
	accountName        string // display name of the account: uncasefolded, '*' if not logged in
	accountRegDate     time.Time
	accountSettings    AccountSettings
	awayMessage        string
	channels           ChannelSet
	ctime              time.Time
	destroyed          bool
	modes              modes.ModeSet
	hostname           string
	invitedTo          map[string]channelInvite
	isSTSOnly          bool
	isKlined           bool // #1941: k-line kills are special-cased to suppress some triggered notices/events
	languages          []string
	lastActive         time.Time            // last time they sent a command that wasn't PONG or similar
	lastSeen           map[string]time.Time // maps device ID (including "") to time of last received command
	readMarkers        map[string]time.Time // maps casefolded target to time of last read marker
	loginThrottle      connection_limits.GenericThrottle
	nextSessionID      int64 // Incremented when a new session is established
	nick               string
	nickCasefolded     string
	nickMaskCasefolded string
	nickMaskString     string // cache for nickmask string since it's used with lots of replies
	oper               *Oper
	preregNick         string
	proxiedIP          net.IP // actual remote IP if using the PROXY protocol
	rawHostname        string
	cloakedHostname    string
	realname           string
	realIP             net.IP
	requireSASLMessage string
	requireSASL        bool
	registered         bool
	registerCmdSent    bool // already sent the draft/register command, can't send it again
	dirtyTimestamps    bool // lastSeen or readMarkers is dirty
	registrationTimer  *time.Timer
	server             *Server
	skeleton           string
	sessions           []*Session
	stateMutex         sync.RWMutex // tier 1
	alwaysOn           bool
	username           string
	vhost              string
	history            history.Buffer
	dirtyBits          uint
	writebackLock      sync.Mutex // tier 1.5
}

type saslStatus struct {
	mechanism string
	value     ircutils.SASLBuffer
	scramConv *scram.ServerConversation
	oauthConv *oauth2.OAuthBearerServer
}

func (s *saslStatus) Initialize() {
	s.value.Initialize(saslMaxResponseLength)
}

func (s *saslStatus) Clear() {
	s.mechanism = ""
	s.value.Clear()
	s.scramConv = nil
	s.oauthConv = nil
}

// what stage the client is at w.r.t. the PASS command:
type serverPassStatus uint

const (
	serverPassUnsent serverPassStatus = iota
	serverPassSuccessful
	serverPassFailed
)

// Session is an individual client connection to the server (TCP connection
// and associated per-connection data, such as capabilities). There is a
// many-one relationship between sessions and clients.
type Session struct {
	client *Client

	deviceID string

	ctime      time.Time
	lastActive time.Time // last non-CTCP PRIVMSG sent; updates publicly visible idle time
	lastTouch  time.Time // last line sent; updates timer for idle timeouts
	idleTimer  *time.Timer
	pingSent   bool // we sent PING to a putatively idle connection and we're waiting for PONG

	sessionID   int64
	socket      *Socket
	realIP      net.IP
	proxiedIP   net.IP
	rawHostname string
	isTor       bool
	hideSTS     bool

	fakelag              Fakelag
	deferredFakelagCount int

	certfp     string
	peerCerts  []*x509.Certificate
	sasl       saslStatus
	passStatus serverPassStatus

	batchCounter atomic.Uint32

	quitMessage string

	awayMessage string
	awayAt      time.Time

	capabilities caps.Set
	capState     caps.State
	capVersion   caps.Version

	registrationMessages int

	zncPlaybackTimes      *zncPlaybackTimes
	autoreplayMissedSince time.Time

	batch MultilineBatch
}

// MultilineBatch tracks the state of a client-to-server multiline batch.
type MultilineBatch struct {
	label         string // this is the first param to BATCH (the "reference tag")
	command       string
	target        string
	responseLabel string // this is the value of the labeled-response tag sent with BATCH
	message       utils.SplitMessage
	lenBytes      int
	tags          map[string]string
}

// Starts a multiline batch, failing if there's one already open
func (s *Session) StartMultilineBatch(label, target, responseLabel string, tags map[string]string) (err error) {
	if s.batch.label != "" {
		return errInvalidMultilineBatch
	}

	s.batch.label, s.batch.target, s.batch.responseLabel, s.batch.tags = label, target, responseLabel, tags
	s.fakelag.Suspend()
	return
}

// Closes a multiline batch unconditionally; returns the batch and whether
// it was validly terminated (pass "" as the label if you don't care about the batch)
func (s *Session) EndMultilineBatch(label string) (batch MultilineBatch, err error) {
	batch = s.batch
	s.batch = MultilineBatch{}
	s.fakelag.Unsuspend()

	// heuristics to estimate how much data they used while fakelag was suspended
	fakelagBill := (batch.lenBytes / MaxLineLen) + 1
	fakelagBillLines := (batch.message.LenLines() * 60) / MaxLineLen
	if fakelagBill < fakelagBillLines {
		fakelagBill = fakelagBillLines
	}
	s.deferredFakelagCount = fakelagBill

	if batch.label == "" || batch.label != label || !batch.message.ValidMultiline() {
		err = errInvalidMultilineBatch
		return
	}

	batch.message.SetTime()

	return
}

// sets the session quit message, if there isn't one already
func (sd *Session) setQuitMessage(message string) (set bool) {
	if message == "" {
		message = "Connection closed"
	}
	if sd.quitMessage == "" {
		sd.quitMessage = message
		return true
	} else {
		return false
	}
}

func (s *Session) IP() net.IP {
	if s.proxiedIP != nil {
		return s.proxiedIP
	}
	return s.realIP
}

// returns whether the client supports a smart history replay cap,
// and therefore autoreplay-on-join and similar should be suppressed
func (session *Session) HasHistoryCaps() bool {
	return session.capabilities.Has(caps.Chathistory) || session.capabilities.Has(caps.ZNCPlayback)
}

// generates a batch ID. the uniqueness requirements for this are fairly weak:
// any two batch IDs that are active concurrently (either through interleaving
// or nesting) on an individual session connection need to be unique.
// this allows ~4 billion such batches which should be fine.
func (session *Session) generateBatchID() string {
	id := session.batchCounter.Add(1)
	return strconv.FormatInt(int64(id), 32)
}

// WhoWas is the subset of client details needed to answer a WHOWAS query
type WhoWas struct {
	nick           string
	nickCasefolded string
	username       string
	hostname       string
	realname       string
	ip             net.IP
	// technically not required for WHOWAS:
	account     string
	accountName string
}

// ClientDetails is a standard set of details about a client
type ClientDetails struct {
	WhoWas

	nickMask           string
	nickMaskCasefolded string
}

// RunClient sets up a new client and runs its goroutine.
func (server *Server) RunClient(conn IRCConn) {
	config := server.Config()
	wConn := conn.UnderlyingConn()
	var isBanned, requireSASL bool
	var banMsg string
	realIP := utils.AddrToIP(wConn.RemoteAddr())
	var proxiedIP net.IP
	if wConn.Tor {
		// cover up details of the tor proxying infrastructure (not a user privacy concern,
		// but a hardening measure):
		proxiedIP = utils.IPv4LoopbackAddress
		isBanned, banMsg = server.checkTorLimits()
	} else {
		ipToCheck := realIP
		if wConn.ProxiedIP != nil {
			proxiedIP = wConn.ProxiedIP
			ipToCheck = proxiedIP
		}
		// XXX only run the check script now if the IP cannot be replaced by PROXY or WEBIRC,
		// otherwise we'll do it in ApplyProxiedIP.
		checkScripts := proxiedIP != nil || !utils.IPInNets(realIP, config.Server.proxyAllowedFromNets)
		isBanned, requireSASL, banMsg = server.checkBans(config, ipToCheck, checkScripts)
	}

	if isBanned {
		// this might not show up properly on some clients,
		// but our objective here is just to close the connection out before it has a load impact on us
		conn.WriteLine([]byte(fmt.Sprintf(errorMsg, banMsg)))
		conn.Close()
		return
	}

	server.logger.Info("connect-ip", fmt.Sprintf("Client connecting: real IP %v, proxied IP %v", realIP, proxiedIP))

	now := time.Now().UTC()
	// give them 1k of grace over the limit:
	socket := NewSocket(conn, config.Server.MaxSendQBytes)
	client := &Client{
		lastActive: now,
		channels:   make(ChannelSet),
		ctime:      now,
		isSTSOnly:  wConn.STSOnly,
		languages:  server.Languages().Default(),
		loginThrottle: connection_limits.GenericThrottle{
			Duration: config.Accounts.LoginThrottling.Duration,
			Limit:    config.Accounts.LoginThrottling.MaxAttempts,
		},
		server:         server,
		accountName:    "*",
		nick:           "*", // * is used until actual nick is given
		nickCasefolded: "*",
		nickMaskString: "*", // * is used until actual nick is given
		realIP:         realIP,
		proxiedIP:      proxiedIP,
		requireSASL:    requireSASL,
		nextSessionID:  1,
	}
	if requireSASL {
		client.requireSASLMessage = banMsg
	}
	client.history.Initialize(config.History.ClientLength, time.Duration(config.History.AutoresizeWindow))
	session := &Session{
		client:     client,
		socket:     socket,
		capVersion: caps.Cap301,
		capState:   caps.NoneState,
		ctime:      now,
		lastActive: now,
		realIP:     realIP,
		proxiedIP:  proxiedIP,
		isTor:      wConn.Tor,
		hideSTS:    wConn.Tor || wConn.HideSTS,
	}
	session.sasl.Initialize()
	client.sessions = []*Session{session}

	session.resetFakelag()

	if wConn.Secure {
		client.SetMode(modes.TLS, true)
	}

	if wConn.TLS {
		// error is not useful to us here anyways so we can ignore it
		session.certfp, session.peerCerts, _ = utils.GetCertFP(wConn.Conn, RegisterTimeout)
	}

	if session.isTor {
		session.rawHostname = config.Server.TorListeners.Vhost
		client.rawHostname = session.rawHostname
	} else {
		if config.Server.CheckIdent {
			client.doIdentLookup(wConn.Conn)
		}
	}

	client.registrationTimer = time.AfterFunc(RegisterTimeout, client.handleRegisterTimeout)
	server.stats.Add()
	client.run(session)
}

func (server *Server) AddAlwaysOnClient(account ClientAccount, channelToStatus map[string]alwaysOnChannelStatus, lastSeen, readMarkers map[string]time.Time, uModes modes.Modes, realname string) {
	now := time.Now().UTC()
	config := server.Config()
	if lastSeen == nil && account.Settings.AutoreplayMissed {
		lastSeen = map[string]time.Time{"": now}
	}

	rawHostname, cloakedHostname := server.name, ""
	if config.Server.Cloaks.EnabledForAlwaysOn {
		cloakedHostname = config.Server.Cloaks.ComputeAccountCloak(account.Name)
	}

	username := "~u"
	if config.Server.CoerceIdent != "" {
		username = config.Server.CoerceIdent
	}

	client := &Client{
		lastSeen:    lastSeen,
		readMarkers: readMarkers,
		lastActive:  now,
		channels:    make(ChannelSet),
		ctime:       now,
		languages:   server.Languages().Default(),
		server:      server,

		username:        username,
		cloakedHostname: cloakedHostname,
		rawHostname:     rawHostname,
		realIP:          utils.IPv4LoopbackAddress,

		alwaysOn: true,
		realname: realname,

		nextSessionID: 1,
	}

	if client.checkAlwaysOnExpirationNoMutex(config, true) {
		server.logger.Debug("accounts", "always-on client not created due to expiration", account.Name)
		return
	}

	client.SetMode(modes.TLS, true)
	for _, m := range uModes {
		client.SetMode(m, true)
	}
	client.history.Initialize(0, 0)

	server.accounts.Login(client, account)

	client.resizeHistory(config)

	_, err, _ := server.clients.SetNick(client, nil, account.Name, false)
	if err != nil {
		server.logger.Error("internal", "could not establish always-on client", account.Name, err.Error())
		return
	} else {
		server.logger.Debug("accounts", "established always-on client", account.Name)
	}

	// XXX set this last to avoid confusing SetNick:
	client.registered = true

	for chname, status := range channelToStatus {
		// XXX we're using isSajoin=true, to make these joins succeed even without channel key
		// this is *probably* ok as long as the persisted memberships are accurate
		server.channels.Join(client, chname, "", true, nil)
		if channel := server.channels.Get(chname); channel != nil {
			channel.setMemberStatus(client, status)
		} else {
			server.logger.Error("internal", "could not create channel", chname)
		}
	}

	if persistenceEnabled(config.Accounts.Multiclient.AutoAway, client.accountSettings.AutoAway) {
		client.setAutoAwayNoMutex(config)
	}
}

func (client *Client) resizeHistory(config *Config) {
	status, _ := client.historyStatus(config)
	if status == HistoryEphemeral {
		client.history.Resize(config.History.ClientLength, time.Duration(config.History.AutoresizeWindow))
	} else {
		client.history.Resize(0, 0)
	}
}

// resolve an IP to an IRC-ready hostname, using reverse DNS, forward-confirming if necessary,
// and sending appropriate notices to the client
func (client *Client) lookupHostname(session *Session, overwrite bool) {
	if session.isTor {
		return
	} // else: even if cloaking is enabled, look up the real hostname to show to operators

	config := client.server.Config()
	ip := session.realIP
	if session.proxiedIP != nil {
		ip = session.proxiedIP
	}

	var hostname string
	lookupSuccessful := false
	if config.Server.lookupHostnames {
		session.Notice("*** Looking up your hostname...")
		hostname, lookupSuccessful = utils.LookupHostname(ip, config.Server.ForwardConfirmHostnames)
		if lookupSuccessful {
			session.Notice("*** Found your hostname")
		} else {
			session.Notice("*** Couldn't look up your hostname")
		}
	} else {
		hostname = utils.IPStringToHostname(ip.String())
	}

	session.rawHostname = hostname
	cloakedHostname := config.Server.Cloaks.ComputeCloak(ip)
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	// update the hostname if this is a new connection, but not if it's a reattach
	if overwrite || client.rawHostname == "" {
		client.rawHostname = hostname
		client.cloakedHostname = cloakedHostname
		client.updateNickMaskNoMutex()
	}
}

func (client *Client) doIdentLookup(conn net.Conn) {
	localTCPAddr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	serverPort := localTCPAddr.Port
	remoteTCPAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	clientPort := remoteTCPAddr.Port

	client.Notice(client.t("*** Looking up your username"))
	resp, err := ident.Query(remoteTCPAddr.IP.String(), serverPort, clientPort, IdentTimeout)
	if err == nil {
		err := client.SetNames(resp.Identifier, "", true)
		if err == nil {
			client.Notice(client.t("*** Found your username"))
			// we don't need to updateNickMask here since nickMask is not used for anything yet
		} else {
			client.Notice(client.t("*** Got a malformed username, ignoring"))
		}
	} else {
		client.Notice(client.t("*** Could not find your username"))
	}
}

type AuthOutcome uint

const (
	authSuccess AuthOutcome = iota
	authFailPass
	authFailTorSaslRequired
	authFailSaslRequired
)

func (client *Client) isAuthorized(server *Server, config *Config, session *Session, forceRequireSASL bool) AuthOutcome {
	saslSent := client.account != ""
	// PASS requirement
	if (config.Server.passwordBytes != nil) && session.passStatus != serverPassSuccessful && !(config.Accounts.SkipServerPassword && saslSent) {
		return authFailPass
	}
	// Tor connections may be required to authenticate with SASL
	if session.isTor && !saslSent && (config.Server.TorListeners.RequireSasl || server.Defcon() <= 4) {
		return authFailTorSaslRequired
	}
	// finally, enforce require-sasl
	if !saslSent && (forceRequireSASL || config.Accounts.RequireSasl.Enabled || server.Defcon() <= 2) &&
		!utils.IPInNets(session.IP(), config.Accounts.RequireSasl.exemptedNets) {
		return authFailSaslRequired
	}
	return authSuccess
}

func (session *Session) resetFakelag() {
	var flc FakelagConfig = session.client.server.Config().Fakelag
	flc.Enabled = flc.Enabled && !session.client.HasRoleCapabs("nofakelag")
	session.fakelag.Initialize(flc)
}

// IP returns the IP address of this client.
func (client *Client) IP() net.IP {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()

	return client.getIPNoMutex()
}

func (client *Client) getIPNoMutex() net.IP {
	if client.proxiedIP != nil {
		return client.proxiedIP
	}
	return client.realIP
}

// IPString returns the IP address of this client as a string.
func (client *Client) IPString() string {
	return utils.IPStringToHostname(client.IP().String())
}

// t returns the translated version of the given string, based on the languages configured by the client.
func (client *Client) t(originalString string) string {
	languageManager := client.server.Config().languageManager
	if !languageManager.Enabled() {
		return originalString
	}
	return languageManager.Translate(client.Languages(), originalString)
}

// main client goroutine: read lines and execute the corresponding commands
// `proxyLine` is the PROXY-before-TLS line, if there was one
func (client *Client) run(session *Session) {

	defer func() {
		if r := recover(); r != nil {
			client.server.logger.Error("internal",
				fmt.Sprintf("Client caused panic: %v\n%s", r, debug.Stack()))
			if client.server.Config().Debug.recoverFromErrors {
				client.server.logger.Error("internal", "Disconnecting client and attempting to recover")
			} else {
				panic(r)
			}
		}
		// ensure client connection gets closed
		client.destroy(session)
	}()

	isReattach := client.Registered()
	if isReattach {
		client.Touch(session)
		client.playReattachMessages(session)
	}

	firstLine := !isReattach

	for {
		var invalidUtf8 bool
		line, err := session.socket.Read()
		if err == errInvalidUtf8 {
			invalidUtf8 = true // handle as normal, including labeling
		} else if err != nil {
			client.server.logger.Debug("connect-ip", "read error from client", err.Error())
			var quitMessage string
			switch err {
			case ircreader.ErrReadQ:
				quitMessage = err.Error()
			default:
				quitMessage = "connection closed"
			}
			client.Quit(quitMessage, session)
			break
		}

		if client.server.logger.IsLoggingRawIO() {
			client.server.logger.Debug("userinput", client.nick, "<- ", line)
		}

		// special-cased handling of PROXY protocol, see `handleProxyCommand` for details:
		if firstLine {
			firstLine = false
			if strings.HasPrefix(line, "PROXY") {
				err = handleProxyCommand(client.server, client, session, line)
				if err != nil {
					break
				} else {
					continue
				}
			}
		}

		msg, err := ircmsg.ParseLineStrict(line, true, MaxLineLen)
		// XXX defer processing of command error parsing until after fakelag

		if client.registered {
			// apply deferred fakelag
			for i := 0; i < session.deferredFakelagCount; i++ {
				session.fakelag.Touch("")
			}
			session.deferredFakelagCount = 0
			// touch for the current command
			var command string
			if err == nil {
				command = msg.Command
			}
			session.fakelag.Touch(command)
		} else {
			// DoS hardening, #505
			session.registrationMessages++
			if client.server.Config().Limits.RegistrationMessages < session.registrationMessages {
				client.Send(nil, client.server.name, ERR_UNKNOWNERROR, "*", client.t("You have sent too many registration messages"))
				break
			}
		}

		if err == ircmsg.ErrorLineIsEmpty {
			continue
		} else if err == ircmsg.ErrorTagsTooLong {
			session.Send(nil, client.server.name, ERR_INPUTTOOLONG, client.Nick(), client.t("Input line contained excess tag data"))
			continue
		} else if err == ircmsg.ErrorBodyTooLong {
			if !client.server.Config().Server.Compatibility.allowTruncation {
				session.Send(nil, client.server.name, ERR_INPUTTOOLONG, client.Nick(), client.t("Input line too long"))
				continue
			} // else: proceed with the truncated line
		} else if err != nil {
			client.Quit(client.t("Received malformed line"), session)
			break
		}

		cmd, exists := Commands[msg.Command]
		if !exists {
			cmd = unknownCommand
		} else if invalidUtf8 {
			cmd = invalidUtf8Command
		}

		isExiting := cmd.Run(client.server, client, session, msg)
		if isExiting {
			break
		} else if session.client != client {
			// bouncer reattach
			go session.client.run(session)
			break
		}
	}
}

func (client *Client) playReattachMessages(session *Session) {
	client.server.playRegistrationBurst(session)
	hasHistoryCaps := session.HasHistoryCaps()
	for _, channel := range session.client.Channels() {
		channel.playJoinForSession(session)
		// clients should receive autoreplay-on-join lines, if applicable:
		if hasHistoryCaps {
			continue
		}
		// if they negotiated znc.in/playback or chathistory, they will receive nothing,
		// because those caps disable autoreplay-on-join and they haven't sent the relevant
		// *playback PRIVMSG or CHATHISTORY command yet
		rb := NewResponseBuffer(session)
		channel.autoReplayHistory(client, rb, "")
		rb.Send(true)
	}
	if !session.autoreplayMissedSince.IsZero() && !hasHistoryCaps {
		rb := NewResponseBuffer(session)
		zncPlayPrivmsgsFromAll(client, rb, time.Now().UTC(), session.autoreplayMissedSince)
		rb.Send(true)
	}
	session.autoreplayMissedSince = time.Time{}
}

//
// idle, quit, timers and timeouts
//

// Touch indicates that we received a line from the client (so the connection is healthy
// at this time, modulo network latency and fakelag).
func (client *Client) Touch(session *Session) {
	now := time.Now().UTC()
	client.stateMutex.Lock()
	if client.registered {
		client.updateIdleTimer(session, now)
		if client.alwaysOn {
			client.setLastSeen(now, session.deviceID)
			client.dirtyTimestamps = true
		}
	}
	client.stateMutex.Unlock()
}

func (client *Client) setLastSeen(now time.Time, deviceID string) {
	if client.lastSeen == nil {
		client.lastSeen = make(map[string]time.Time)
	}
	updateLRUMap(client.lastSeen, deviceID, now, maxDeviceIDsPerClient)
}

func (client *Client) updateIdleTimer(session *Session, now time.Time) {
	session.lastTouch = now
	session.pingSent = false

	if session.idleTimer == nil {
		pingTimeout := DefaultIdleTimeout
		if session.isTor {
			pingTimeout = TorIdleTimeout
		}
		session.idleTimer = time.AfterFunc(pingTimeout, session.handleIdleTimeout)
	}
}

func (session *Session) handleIdleTimeout() {
	totalTimeout := DefaultTotalTimeout
	pingTimeout := DefaultIdleTimeout
	if session.isTor {
		pingTimeout = TorIdleTimeout
	}

	session.client.stateMutex.Lock()
	now := time.Now()
	timeUntilDestroy := session.lastTouch.Add(totalTimeout).Sub(now)
	timeUntilPing := session.lastTouch.Add(pingTimeout).Sub(now)
	shouldDestroy := session.pingSent && timeUntilDestroy <= 0
	// XXX this should really be time <= 0, but let's do some hacky timer coalescing:
	// a typical idling client will do nothing other than respond immediately to our pings,
	// so we'll PING at t=0, they'll respond at t=0.05, then we'll wake up at t=90 and find
	// that we need to PING again at t=90.05. Rather than wake up again, just send it now:
	shouldSendPing := !session.pingSent && timeUntilPing <= PingCoalesceThreshold
	if !shouldDestroy {
		if shouldSendPing {
			session.pingSent = true
		}
		// check in again at the minimum of these 3 possible intervals:
		// 1. the ping timeout (assuming we PING and they reply immediately with PONG)
		// 2. the next time we would send PING (if they don't send any more lines)
		// 3. the next time we would destroy (if they don't send any more lines)
		nextTimeout := pingTimeout
		if PingCoalesceThreshold < timeUntilPing && timeUntilPing < nextTimeout {
			nextTimeout = timeUntilPing
		}
		if 0 < timeUntilDestroy && timeUntilDestroy < nextTimeout {
			nextTimeout = timeUntilDestroy
		}
		session.idleTimer.Stop()
		session.idleTimer.Reset(nextTimeout)
	}
	session.client.stateMutex.Unlock()

	if shouldDestroy {
		session.client.Quit(fmt.Sprintf("Ping timeout: %v", totalTimeout), session)
		session.client.destroy(session)
	} else if shouldSendPing {
		session.Ping()
	}
}

func (session *Session) stopIdleTimer() {
	session.client.stateMutex.Lock()
	defer session.client.stateMutex.Unlock()
	if session.idleTimer != nil {
		session.idleTimer.Stop()
	}
}

// Ping sends the client a PING message.
func (session *Session) Ping() {
	session.Send(nil, "", "PING", session.client.Nick())
}

func (client *Client) replayPrivmsgHistory(rb *ResponseBuffer, items []history.Item, target string, chathistoryCommand bool) {
	var batchID string
	details := client.Details()
	nick := details.nick
	if target == "" {
		target = nick
	}
	batchID = rb.StartNestedBatch("chathistory", target)

	isSelfMessage := func(item *history.Item) bool {
		// XXX: Params[0] is the message target. if the source of this message is an in-memory
		// buffer, then it's "" for an incoming message and the recipient's nick for an outgoing
		// message. if the source of the message is mysql, then mysql only sees one copy of the
		// message, and it's the version with the recipient's nick filled in. so this is an
		// incoming message if Params[0] (the recipient's nick) equals the client's nick:
		return item.Params[0] != "" && item.Params[0] != nick
	}

	hasEventPlayback := rb.session.capabilities.Has(caps.EventPlayback)
	hasTags := rb.session.capabilities.Has(caps.MessageTags)
	for _, item := range items {
		var command string
		switch item.Type {
		case history.Invite:
			if isSelfMessage(&item) {
				continue
			}
			if hasEventPlayback {
				rb.AddFromClient(item.Message.Time, item.Message.Msgid, item.Nick, item.AccountName, item.IsBot, nil, "INVITE", nick, item.Message.Message)
			} else {
				rb.AddFromClient(item.Message.Time, history.HistservMungeMsgid(item.Message.Msgid), histservService.prefix, "*", false, nil, "PRIVMSG", fmt.Sprintf(client.t("%[1]s invited you to channel %[2]s"), NUHToNick(item.Nick), item.Message.Message))
			}
			continue
		case history.Privmsg:
			command = "PRIVMSG"
		case history.Notice:
			command = "NOTICE"
		case history.Tagmsg:
			if hasEventPlayback && hasTags {
				command = "TAGMSG"
			} else if chathistoryCommand {
				// #1676: send something for TAGMSG; we can't discard it entirely
				// because it'll break pagination
				rb.AddFromClient(item.Message.Time, history.HistservMungeMsgid(item.Message.Msgid), histservService.prefix, "*", false, nil, "PRIVMSG", fmt.Sprintf(client.t("%[1]s sent you a TAGMSG"), NUHToNick(item.Nick)))
			} else {
				continue
			}
		default:
			// see #1676, this shouldn't happen
			continue
		}
		var tags map[string]string
		if hasTags {
			tags = item.Tags
		}
		if !isSelfMessage(&item) {
			rb.AddSplitMessageFromClient(item.Nick, item.AccountName, item.IsBot, tags, command, nick, item.Message)
		} else {
			// this message was sent *from* the client to another nick; the target is item.Params[0]
			// substitute client's current nickmask in case client changed nick
			rb.AddSplitMessageFromClient(details.nickMask, item.AccountName, item.IsBot, tags, command, item.Params[0], item.Message)
		}
	}

	rb.EndNestedBatch(batchID)
}

// IdleTime returns how long this client's been idle.
func (client *Client) IdleTime() time.Duration {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return time.Since(client.lastActive)
}

// SignonTime returns this client's signon time as a unix timestamp.
func (client *Client) SignonTime() int64 {
	return client.ctime.Unix()
}

// IdleSeconds returns the number of seconds this client's been idle.
func (client *Client) IdleSeconds() uint64 {
	return uint64(client.IdleTime().Seconds())
}

// SetNames sets the client's ident and realname.
func (client *Client) SetNames(username, realname string, fromIdent bool) error {
	config := client.server.Config()
	limit := config.Limits.IdentLen
	if !fromIdent {
		limit -= 1 // leave room for the prepended ~
	}
	if limit < len(username) {
		username = username[:limit]
	}

	if !isIdent(username) {
		return errInvalidUsername
	}

	if config.Server.CoerceIdent != "" {
		username = config.Server.CoerceIdent
	} else if !fromIdent {
		username = "~" + username
	}

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	if client.username == "" {
		client.username = username
	}

	if client.realname == "" {
		client.realname = realname
	}

	return nil
}

// HasRoleCapabs returns true if client has the given (role) capabilities.
func (client *Client) HasRoleCapabs(capabs ...string) bool {
	oper := client.Oper()
	if oper == nil {
		return false
	}

	for _, capab := range capabs {
		if !oper.Class.Capabilities.Has(capab) {
			return false
		}
	}

	return true
}

// ModeString returns the mode string for this client.
func (client *Client) ModeString() (str string) {
	return "+" + client.modes.String()
}

// Friends refers to clients that share a channel with this client.
func (client *Client) Friends(capabs ...caps.Capability) (result utils.HashSet[*Session]) {
	result = make(utils.HashSet[*Session])

	// look at the client's own sessions
	addFriendsToSet(result, client, capabs...)

	for _, channel := range client.Channels() {
		for _, member := range channel.auditoriumFriends(client) {
			addFriendsToSet(result, member, capabs...)
		}
	}

	return
}

// Friends refers to clients that share a channel or extended-monitor this client.
func (client *Client) FriendsMonitors(capabs ...caps.Capability) (result utils.HashSet[*Session]) {
	result = client.Friends(capabs...)
	client.server.monitorManager.AddMonitors(result, client.nickCasefolded, capabs...)
	return
}

// helper for Friends
func addFriendsToSet(set utils.HashSet[*Session], client *Client, capabs ...caps.Capability) {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	for _, session := range client.sessions {
		if session.capabilities.HasAll(capabs...) {
			set.Add(session)
		}
	}
}

func (client *Client) SetOper(oper *Oper) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	client.oper = oper
	// operators typically get a vhost, update the nickmask
	client.updateNickMaskNoMutex()
}

// XXX: CHGHOST requires prefix nickmask to have original hostname,
// this is annoying to do correctly
func (client *Client) sendChghost(oldNickMask string, vhost string) {
	details := client.Details()
	isBot := client.HasMode(modes.Bot)
	for fClient := range client.FriendsMonitors(caps.ChgHost) {
		fClient.sendFromClientInternal(false, time.Time{}, "", oldNickMask, details.accountName, isBot, nil, "CHGHOST", details.username, vhost)
	}
}

// choose the correct vhost to display
func (client *Client) getVHostNoMutex() string {
	// hostserv vhost OR operclass vhost OR nothing (i.e., normal rdns hostmask)
	if client.vhost != "" {
		return client.vhost
	} else if client.oper != nil && !client.oper.Hidden {
		return client.oper.Vhost
	} else {
		return ""
	}
}

// SetVHost updates the client's hostserv-based vhost
func (client *Client) SetVHost(vhost string) (updated bool) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	updated = (client.vhost != vhost)
	client.vhost = vhost
	if updated {
		client.updateNickMaskNoMutex()
	}
	return
}

// SetNick gives the client a nickname and marks it as registered, if necessary
func (client *Client) SetNick(nick, nickCasefolded, skeleton string) (success bool) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	if client.destroyed {
		return false
	} else if !client.registered {
		// XXX test this before setting it to avoid annoying the race detector
		client.registered = true
		if client.registrationTimer != nil {
			client.registrationTimer.Stop()
			client.registrationTimer = nil
		}
	}
	client.nick = nick
	client.nickCasefolded = nickCasefolded
	client.skeleton = skeleton
	client.updateNickMaskNoMutex()
	return true
}

// updateNickMaskNoMutex updates the casefolded nickname and nickmask, not acquiring any mutexes.
func (client *Client) updateNickMaskNoMutex() {
	if client.nick == "*" {
		return // pre-registration, don't bother generating the hostname
	}

	client.hostname = client.getVHostNoMutex()
	if client.hostname == "" {
		client.hostname = client.cloakedHostname
		if client.hostname == "" {
			client.hostname = client.rawHostname
		}
	}

	cfhostname := strings.ToLower(client.hostname)
	client.nickMaskString = fmt.Sprintf("%s!%s@%s", client.nick, client.username, client.hostname)
	client.nickMaskCasefolded = fmt.Sprintf("%s!%s@%s", client.nickCasefolded, strings.ToLower(client.username), cfhostname)
}

// AllNickmasks returns all the possible nickmasks for the client.
func (client *Client) AllNickmasks() (masks []string) {
	client.stateMutex.RLock()
	nick := client.nickCasefolded
	username := client.username
	rawHostname := client.rawHostname
	cloakedHostname := client.cloakedHostname
	vhost := client.getVHostNoMutex()
	client.stateMutex.RUnlock()
	username = strings.ToLower(username)

	if len(vhost) > 0 {
		cfvhost := strings.ToLower(vhost)
		masks = append(masks, fmt.Sprintf("%s!%s@%s", nick, username, cfvhost))
	}

	var rawhostmask string
	cfrawhost := strings.ToLower(rawHostname)
	rawhostmask = fmt.Sprintf("%s!%s@%s", nick, username, cfrawhost)
	masks = append(masks, rawhostmask)

	if cloakedHostname != "" {
		masks = append(masks, fmt.Sprintf("%s!%s@%s", nick, username, cloakedHostname))
	}

	ipmask := fmt.Sprintf("%s!%s@%s", nick, username, client.IPString())
	if ipmask != rawhostmask {
		masks = append(masks, ipmask)
	}

	return
}

// LoggedIntoAccount returns true if this client is logged into an account.
func (client *Client) LoggedIntoAccount() bool {
	return client.Account() != ""
}

// Quit sets the given quit message for the client.
// (You must ensure separately that destroy() is called, e.g., by returning `true` from
// the command handler or calling it yourself.)
func (client *Client) Quit(message string, session *Session) {
	setFinalData := func(sess *Session) {
		message := sess.quitMessage
		var finalData []byte
		// #364: don't send QUIT lines to unregistered clients
		if client.registered {
			quitMsg := ircmsg.MakeMessage(nil, client.nickMaskString, "QUIT", message)
			finalData, _ = quitMsg.LineBytesStrict(false, MaxLineLen)
		}

		errorMsg := ircmsg.MakeMessage(nil, "", "ERROR", message)
		errorMsgBytes, _ := errorMsg.LineBytesStrict(false, MaxLineLen)
		finalData = append(finalData, errorMsgBytes...)

		sess.socket.SetFinalData(finalData)
	}

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	var sessions []*Session
	if session != nil {
		sessions = []*Session{session}
	} else {
		sessions = client.sessions
	}

	for _, session := range sessions {
		if session.setQuitMessage(message) {
			setFinalData(session)
		}
	}
}

// destroy gets rid of a client, removes them from server lists etc.
// if `session` is nil, destroys the client unconditionally, removing all sessions;
// otherwise, destroys one specific session, only destroying the client if it
// has no more sessions.
func (client *Client) destroy(session *Session) {
	config := client.server.Config()
	var sessionsToDestroy []*Session
	var quitMessage string

	client.stateMutex.Lock()

	details := client.detailsNoMutex()
	sessionRemoved := false
	registered := client.registered
	isKlined := client.isKlined
	// XXX a temporary (reattaching) client can be marked alwaysOn when it logs in,
	// but then the session attaches to another client and we need to clean it up here
	alwaysOn := registered && client.alwaysOn
	// if we hit always-on-expiration, confirm the expiration and then proceed as though
	// always-on is disabled:
	if alwaysOn && session == nil && client.checkAlwaysOnExpirationNoMutex(config, false) {
		quitMessage = "Timed out due to inactivity"
		alwaysOn = false
		client.alwaysOn = false
	}

	var remainingSessions int
	if session == nil {
		sessionsToDestroy = client.sessions
		client.sessions = nil
		remainingSessions = 0
	} else {
		sessionRemoved, remainingSessions = client.removeSession(session)
		if sessionRemoved {
			sessionsToDestroy = []*Session{session}
		}
	}

	// should we destroy the whole client this time?
	shouldDestroy := !client.destroyed && remainingSessions == 0 && !alwaysOn
	// decrement stats on a true destroy, or for the removal of the last connected session
	// of an always-on client
	shouldDecrement := shouldDestroy || (alwaysOn && len(sessionsToDestroy) != 0 && len(client.sessions) == 0)
	if shouldDestroy {
		// if it's our job to destroy it, don't let anyone else try
		client.destroyed = true
	}

	wasAway := client.awayMessage
	if client.autoAwayEnabledNoMutex(config) {
		client.setAutoAwayNoMutex(config)
	}
	nowAway := client.awayMessage

	if client.registrationTimer != nil {
		// unconditionally stop; if the client is still unregistered it must be destroyed
		client.registrationTimer.Stop()
	}

	client.stateMutex.Unlock()

	// destroy all applicable sessions:
	for _, session := range sessionsToDestroy {
		if session.client != client {
			// session has been attached to a new client; do not destroy it
			continue
		}
		session.stopIdleTimer()
		// send quit/error message to client if they haven't been sent already
		client.Quit("", session)
		quitMessage = session.quitMessage // doesn't need synch, we already detached
		session.socket.Close()

		// clean up monitor state
		client.server.monitorManager.RemoveAll(session)

		// remove from connection limits
		var source string
		if session.isTor {
			client.server.torLimiter.RemoveClient()
			source = "tor"
		} else {
			ip := session.realIP
			if session.proxiedIP != nil {
				ip = session.proxiedIP
			}
			client.server.connectionLimiter.RemoveClient(flatip.FromNetIP(ip))
			source = ip.String()
		}
		if !shouldDestroy {
			client.server.snomasks.Send(sno.LocalDisconnects, fmt.Sprintf(ircfmt.Unescape("Client session disconnected for [a:%s] [h:%s] [ip:%s]"), details.accountName, session.rawHostname, source))
		}
		client.server.logger.Info("connect-ip", fmt.Sprintf("disconnecting session of %s from %s", details.nick, source))
	}

	// decrement stats if we have no more sessions, even if the client will not be destroyed
	if shouldDecrement {
		invisible := client.HasMode(modes.Invisible)
		operator := client.HasMode(modes.Operator)
		client.server.stats.Remove(registered, invisible, operator)
	}

	if !shouldDestroy && wasAway != nowAway {
		dispatchAwayNotify(client, nowAway)
	}

	if !shouldDestroy {
		return
	}

	var quitItem history.Item
	var quitHistoryChannels []*Channel
	// use a defer here to avoid writing to mysql while holding the destroy semaphore:
	defer func() {
		for _, channel := range quitHistoryChannels {
			channel.AddHistoryItem(quitItem, details.account)
		}
	}()

	// see #235: deduplicating the list of PART recipients uses (comparatively speaking)
	// a lot of RAM, so limit concurrency to avoid thrashing
	client.server.semaphores.ClientDestroy.Acquire()
	defer client.server.semaphores.ClientDestroy.Release()

	if registered {
		client.server.whoWas.Append(client.WhoWas())
	}

	// alert monitors
	if registered {
		client.server.monitorManager.AlertAbout(details.nick, details.nickCasefolded, false)
	}

	// clean up channels
	// (note that if this is a reattach, client has no channels and therefore no friends)
	friends := make(ClientSet)
	channels := client.Channels()
	for _, channel := range channels {
		if channel.memberIsVisible(client) {
			quitHistoryChannels = append(quitHistoryChannels, channel)
		}
		for _, member := range channel.auditoriumFriends(client) {
			friends.Add(member)
		}
		channel.Quit(client)
	}
	friends.Remove(client)

	// clean up server
	client.server.clients.Remove(client)
	client.server.accepts.Remove(client)
	client.server.accounts.Logout(client)

	if quitMessage == "" {
		quitMessage = "Exited"
	}
	splitQuitMessage := utils.MakeMessage(quitMessage)
	isBot := client.HasMode(modes.Bot)
	quitItem = history.Item{
		Type:        history.Quit,
		Nick:        details.nickMask,
		AccountName: details.accountName,
		Message:     splitQuitMessage,
		IsBot:       isBot,
	}
	var cache MessageCache
	cache.Initialize(client.server, splitQuitMessage.Time, splitQuitMessage.Msgid, details.nickMask, details.accountName, isBot, nil, "QUIT", quitMessage)
	for friend := range friends {
		for _, session := range friend.Sessions() {
			cache.Send(session)
		}
	}

	if registered {
		if !isKlined {
			client.server.snomasks.Send(sno.LocalQuits, fmt.Sprintf(ircfmt.Unescape("%s$r exited the network"), details.nick))
			client.server.logger.Info("quit", fmt.Sprintf("%s is no longer on the server", details.nick))
		}
	}
}

// SendSplitMsgFromClient sends an IRC PRIVMSG/NOTICE coming from a specific client.
// Adds account-tag to the line as well.
func (session *Session) sendSplitMsgFromClientInternal(blocking bool, nickmask, accountName string, isBot bool, tags map[string]string, command, target string, message utils.SplitMessage) {
	if message.Is512() {
		session.sendFromClientInternal(blocking, message.Time, message.Msgid, nickmask, accountName, isBot, tags, command, target, message.Message)
	} else {
		if session.capabilities.Has(caps.Multiline) {
			for _, msg := range composeMultilineBatch(session.generateBatchID(), nickmask, accountName, isBot, tags, command, target, message) {
				session.SendRawMessage(msg, blocking)
			}
		} else {
			msgidSent := false // send msgid on the first nonblank line
			for _, messagePair := range message.Split {
				if len(messagePair.Message) == 0 {
					continue
				}
				var msgid string
				if !msgidSent {
					msgidSent = true
					msgid = message.Msgid
				}
				session.sendFromClientInternal(blocking, message.Time, msgid, nickmask, accountName, isBot, tags, command, target, messagePair.Message)
			}
		}
	}
}

func (session *Session) sendFromClientInternal(blocking bool, serverTime time.Time, msgid string, nickmask, accountName string, isBot bool, tags map[string]string, command string, params ...string) (err error) {
	msg := ircmsg.MakeMessage(tags, nickmask, command, params...)
	// attach account-tag
	if session.capabilities.Has(caps.AccountTag) && accountName != "*" {
		msg.SetTag("account", accountName)
	}
	// attach message-id
	if msgid != "" && session.capabilities.Has(caps.MessageTags) {
		msg.SetTag("msgid", msgid)
	}
	// attach server-time
	session.setTimeTag(&msg, serverTime)
	// attach bot tag
	if isBot && session.capabilities.Has(caps.MessageTags) {
		msg.SetTag(caps.BotTagName, "")
	}

	return session.SendRawMessage(msg, blocking)
}

func composeMultilineBatch(batchID, fromNickMask, fromAccount string, isBot bool, tags map[string]string, command, target string, message utils.SplitMessage) (result []ircmsg.Message) {
	batchStart := ircmsg.MakeMessage(tags, fromNickMask, "BATCH", "+"+batchID, caps.MultilineBatchType, target)
	batchStart.SetTag("time", message.Time.Format(IRCv3TimestampFormat))
	batchStart.SetTag("msgid", message.Msgid)
	if fromAccount != "*" {
		batchStart.SetTag("account", fromAccount)
	}
	if isBot {
		batchStart.SetTag(caps.BotTagName, "")
	}
	result = append(result, batchStart)

	for _, msg := range message.Split {
		message := ircmsg.MakeMessage(nil, fromNickMask, command, target, msg.Message)
		message.SetTag("batch", batchID)
		if msg.Concat {
			message.SetTag(caps.MultilineConcatTag, "")
		}
		result = append(result, message)
	}

	result = append(result, ircmsg.MakeMessage(nil, fromNickMask, "BATCH", "-"+batchID))
	return
}

var (
	// in practice, many clients require that the final parameter be a trailing
	// (prefixed with `:`) even when this is not syntactically necessary.
	// by default, force the following commands to use a trailing:
	commandsThatMustUseTrailing = utils.SetLiteral(
		"PRIVMSG",
		"NOTICE",
		RPL_WHOISCHANNELS,
		RPL_USERHOST,
		// mirc's handling of RPL_NAMREPLY is broken:
		// https://forums.mirc.com/ubbthreads.php/topics/266939/re-nick-list
		RPL_NAMREPLY,
	)
)

func forceTrailing(config *Config, command string) bool {
	return config.Server.Compatibility.forceTrailing && commandsThatMustUseTrailing.Has(command)
}

// SendRawMessage sends a raw message to the client.
func (session *Session) SendRawMessage(message ircmsg.Message, blocking bool) error {
	if forceTrailing(session.client.server.Config(), message.Command) {
		message.ForceTrailing()
	}

	// assemble message
	line, err := message.LineBytesStrict(false, MaxLineLen)
	if !(err == nil || err == ircmsg.ErrorBodyTooLong) {
		errorParams := []string{"Error assembling message for sending", err.Error(), message.Command}
		errorParams = append(errorParams, message.Params...)
		session.client.server.logger.Error("internal", errorParams...)

		message = ircmsg.MakeMessage(nil, session.client.server.name, ERR_UNKNOWNERROR, "*", "Error assembling message for sending")
		line, _ := message.LineBytesStrict(false, 0)

		if blocking {
			session.socket.BlockingWrite(line)
		} else {
			session.socket.Write(line)
		}
		return err
	}

	return session.sendBytes(line, blocking)
}

func (session *Session) sendBytes(line []byte, blocking bool) (err error) {
	if session.client.server.logger.IsLoggingRawIO() {
		logline := string(line[:len(line)-2]) // strip "\r\n"
		session.client.server.logger.Debug("useroutput", session.client.Nick(), " ->", logline)
	}

	if blocking {
		err = session.socket.BlockingWrite(line)
	} else {
		err = session.socket.Write(line)
	}
	if err != nil {
		session.client.server.logger.Info("quit", "send error to client", fmt.Sprintf("%s [%d]", session.client.Nick(), session.sessionID), err.Error())
	}
	return err
}

// Send sends an IRC line to the client.
func (client *Client) Send(tags map[string]string, prefix string, command string, params ...string) (err error) {
	for _, session := range client.Sessions() {
		err_ := session.Send(tags, prefix, command, params...)
		if err_ != nil {
			err = err_
		}
	}
	return
}

func (session *Session) Send(tags map[string]string, prefix string, command string, params ...string) (err error) {
	msg := ircmsg.MakeMessage(tags, prefix, command, params...)
	session.setTimeTag(&msg, time.Time{})
	return session.SendRawMessage(msg, false)
}

func (session *Session) setTimeTag(msg *ircmsg.Message, serverTime time.Time) {
	if session.capabilities.Has(caps.ServerTime) && !msg.HasTag("time") {
		if serverTime.IsZero() {
			serverTime = time.Now()
		}
		msg.SetTag("time", serverTime.UTC().Format(IRCv3TimestampFormat))
	}
}

// Notice sends the client a notice from the server.
func (client *Client) Notice(text string) {
	client.Send(nil, client.server.name, "NOTICE", client.Nick(), text)
}

func (session *Session) Notice(text string) {
	session.Send(nil, session.client.server.name, "NOTICE", session.client.Nick(), text)
}

// `simulated` is for the fake join of an always-on client
// (we just read the channel name from the database, there's no need to write it back)
func (client *Client) addChannel(channel *Channel, simulated bool) (err error) {
	config := client.server.Config()

	client.stateMutex.Lock()
	alwaysOn := client.alwaysOn
	if client.destroyed {
		err = errClientDestroyed
	} else if client.oper == nil && len(client.channels) >= config.Channels.MaxChannelsPerClient {
		err = errTooManyChannels
	} else {
		client.channels.Add(channel) // success
	}
	client.stateMutex.Unlock()

	if err == nil && alwaysOn && !simulated {
		client.markDirty(IncludeChannels)
	}
	return
}

func (client *Client) removeChannel(channel *Channel) {
	client.stateMutex.Lock()
	delete(client.channels, channel)
	alwaysOn := client.alwaysOn
	client.stateMutex.Unlock()

	if alwaysOn {
		client.markDirty(IncludeChannels)
	}
}

type channelInvite struct {
	channelCreatedAt time.Time
	invitedAt        time.Time
}

// Records that the client has been invited to join an invite-only channel
func (client *Client) Invite(casefoldedChannel string, channelCreatedAt time.Time) {
	now := time.Now().UTC()
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	if client.invitedTo == nil {
		client.invitedTo = make(map[string]channelInvite)
	}

	client.invitedTo[casefoldedChannel] = channelInvite{
		channelCreatedAt: channelCreatedAt,
		invitedAt:        now,
	}

	return
}

func (client *Client) Uninvite(casefoldedChannel string) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	delete(client.invitedTo, casefoldedChannel)
}

// Checks that the client was invited to join a given channel
func (client *Client) CheckInvited(casefoldedChannel string, createdTime time.Time) (invited bool) {
	config := client.server.Config()
	expTime := time.Duration(config.Channels.InviteExpiration)
	now := time.Now().UTC()

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	curInvite, ok := client.invitedTo[casefoldedChannel]
	if ok {
		// joining an invited channel "uses up" your invite, so you can't rejoin on kick
		delete(client.invitedTo, casefoldedChannel)
	}
	invited = ok && (expTime == time.Duration(0) || now.Sub(curInvite.invitedAt) < expTime) &&
		createdTime.Equal(curInvite.channelCreatedAt)
	return
}

// Implements auto-oper by certfp (scans for an auto-eligible operator block that matches
// the client's cert, then applies it).
func (client *Client) attemptAutoOper(session *Session) {
	if session.certfp == "" || client.HasMode(modes.Operator) {
		return
	}
	for _, oper := range client.server.Config().operators {
		if oper.Auto && oper.Pass == nil && oper.Certfp != "" && oper.Certfp == session.certfp {
			rb := NewResponseBuffer(session)
			applyOper(client, oper, rb)
			rb.Send(true)
			return
		}
	}
}

func (client *Client) checkLoginThrottle() (throttled bool, remainingTime time.Duration) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	return client.loginThrottle.Touch()
}

func (client *Client) historyStatus(config *Config) (status HistoryStatus, target string) {
	if !config.History.Enabled {
		return HistoryDisabled, ""
	}

	client.stateMutex.RLock()
	target = client.account
	historyStatus := client.accountSettings.DMHistory
	client.stateMutex.RUnlock()

	if target == "" {
		return HistoryEphemeral, ""
	}
	status = historyEnabled(config.History.Persistent.DirectMessages, historyStatus)
	if status != HistoryPersistent {
		target = ""
	}
	return
}

func (client *Client) addHistoryItem(target *Client, item history.Item, details, tDetails *ClientDetails, config *Config) (err error) {
	if !itemIsStorable(&item, config) {
		return
	}

	item.Nick = details.nickMask
	item.AccountName = details.accountName
	targetedItem := item
	targetedItem.Params[0] = tDetails.nick

	cStatus, _ := client.historyStatus(config)
	tStatus, _ := target.historyStatus(config)
	// add to ephemeral history
	if cStatus == HistoryEphemeral {
		targetedItem.CfCorrespondent = tDetails.nickCasefolded
		client.history.Add(targetedItem)
	}
	if tStatus == HistoryEphemeral && client != target {
		item.CfCorrespondent = details.nickCasefolded
		target.history.Add(item)
	}
	if cStatus == HistoryPersistent || tStatus == HistoryPersistent {
		targetedItem.CfCorrespondent = ""
		client.server.historyDB.AddDirectMessage(details.nickCasefolded, details.account, tDetails.nickCasefolded, tDetails.account, targetedItem)
	}
	return nil
}

func (client *Client) listTargets(start, end history.Selector, limit int) (results []history.TargetListing, err error) {
	var base, extras []history.TargetListing
	var chcfnames []string
	for _, channel := range client.Channels() {
		_, seq, err := client.server.GetHistorySequence(channel, client, "")
		if seq == nil || err != nil {
			continue
		}
		if seq.Ephemeral() {
			items, err := seq.Between(history.Selector{}, history.Selector{}, 1)
			if err == nil && len(items) != 0 {
				extras = append(extras, history.TargetListing{
					Time:   items[0].Message.Time,
					CfName: channel.NameCasefolded(),
				})
			}
		} else {
			chcfnames = append(chcfnames, channel.NameCasefolded())
		}
	}
	persistentExtras, err := client.server.historyDB.ListChannels(chcfnames)
	if err == nil && len(persistentExtras) != 0 {
		extras = append(extras, persistentExtras...)
	}

	_, cSeq, err := client.server.GetHistorySequence(nil, client, "")
	if err == nil && cSeq != nil {
		correspondents, err := cSeq.ListCorrespondents(start, end, limit)
		if err == nil {
			base = correspondents
		}
	}

	results = history.MergeTargets(base, extras, start.Time, end.Time, limit)
	return results, nil
}

// latest PRIVMSG from all DM targets
func (client *Client) privmsgsBetween(startTime, endTime time.Time, targetLimit, messageLimit int) (results []history.Item, err error) {
	start := history.Selector{Time: startTime}
	end := history.Selector{Time: endTime}
	targets, err := client.listTargets(start, end, targetLimit)
	if err != nil {
		return
	}
	for _, target := range targets {
		if strings.HasPrefix(target.CfName, "#") {
			continue
		}
		_, seq, err := client.server.GetHistorySequence(nil, client, target.CfName)
		if err == nil && seq != nil {
			items, err := seq.Between(start, end, messageLimit)
			if err == nil {
				results = append(results, items...)
			} else {
				client.server.logger.Error("internal", "error querying privmsg history", client.Nick(), target.CfName, err.Error())
			}
		}
	}
	return
}

func (client *Client) handleRegisterTimeout() {
	client.Quit(fmt.Sprintf("Registration timeout: %v", RegisterTimeout), nil)
	client.destroy(nil)
}

func (client *Client) copyLastSeen() (result map[string]time.Time) {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return maps.Clone(client.lastSeen)
}

// these are bit flags indicating what part of the client status is "dirty"
// and needs to be read from memory and written to the db
const (
	IncludeChannels uint = 1 << iota
	IncludeUserModes
	IncludeRealname
)

func (client *Client) markDirty(dirtyBits uint) {
	client.stateMutex.Lock()
	alwaysOn := client.alwaysOn
	client.dirtyBits = client.dirtyBits | dirtyBits
	client.stateMutex.Unlock()

	if alwaysOn {
		client.wakeWriter()
	}
}

func (client *Client) wakeWriter() {
	if client.writebackLock.TryLock() {
		go client.writeLoop()
	}
}

func (client *Client) writeLoop() {
	defer client.server.HandlePanic()

	for {
		client.performWrite(0)
		client.writebackLock.Unlock()

		client.stateMutex.RLock()
		isDirty := client.dirtyBits != 0
		client.stateMutex.RUnlock()

		if !isDirty || !client.writebackLock.TryLock() {
			return
		}
	}
}

func (client *Client) performWrite(additionalDirtyBits uint) {
	client.stateMutex.Lock()
	dirtyBits := client.dirtyBits | additionalDirtyBits
	client.dirtyBits = 0
	account := client.account
	client.stateMutex.Unlock()

	if account == "" {
		client.server.logger.Error("internal", "attempting to persist logged-out client", client.Nick())
		return
	}

	if (dirtyBits & IncludeChannels) != 0 {
		channels := client.Channels()
		channelToModes := make(map[string]alwaysOnChannelStatus, len(channels))
		for _, channel := range channels {
			ok, chname, status := channel.alwaysOnStatus(client)
			if !ok {
				client.server.logger.Error("internal", "client and channel membership out of sync", chname, client.Nick())
				continue
			}
			channelToModes[chname] = status
		}
		client.server.accounts.saveChannels(account, channelToModes)
	}
	if (dirtyBits & IncludeUserModes) != 0 {
		uModes := make(modes.Modes, 0, len(modes.SupportedUserModes))
		for _, m := range modes.SupportedUserModes {
			switch m {
			case modes.Operator, modes.ServerNotice:
				// these can't be persisted because they depend on the operator block
			default:
				if client.HasMode(m) {
					uModes = append(uModes, m)
				}
			}
		}
		client.server.accounts.saveModes(account, uModes)
	}
	if (dirtyBits & IncludeRealname) != 0 {
		client.server.accounts.saveRealname(account, client.realname)
	}
}

// Blocking store; see Channel.Store and Socket.BlockingWrite
func (client *Client) Store(dirtyBits uint) (err error) {
	defer func() {
		client.stateMutex.Lock()
		isDirty := client.dirtyBits != 0
		client.stateMutex.Unlock()

		if isDirty {
			client.wakeWriter()
		}
	}()

	client.writebackLock.Lock()
	defer client.writebackLock.Unlock()
	client.performWrite(dirtyBits)
	return nil
}
