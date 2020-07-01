// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/goshuirc/irc-go/ircmsg"
	ident "github.com/oragono/go-ident"
	"github.com/oragono/oragono/irc/caps"
	"github.com/oragono/oragono/irc/connection_limits"
	"github.com/oragono/oragono/irc/history"
	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/sno"
	"github.com/oragono/oragono/irc/utils"
)

const (
	// IdentTimeout is how long before our ident (username) check times out.
	IdentTimeout         = time.Second + 500*time.Millisecond
	IRCv3TimestampFormat = utils.IRCv3TimestampFormat
	// limit the number of device IDs a client can use, as a DoS mitigation
	maxDeviceIDsPerClient = 64
	// controls how often often we write an autoreplay-missed client's
	// deviceid->lastseentime mapping to the database
	lastSeenWriteInterval = time.Hour
)

// ResumeDetails is a place to stash data at various stages of
// the resume process: when handling the RESUME command itself,
// when completing the registration, and when rejoining channels.
type ResumeDetails struct {
	PresentedToken    string
	Timestamp         time.Time
	HistoryIncomplete bool
}

// Client is an IRC client.
type Client struct {
	account            string
	accountName        string // display name of the account: uncasefolded, '*' if not logged in
	accountRegDate     time.Time
	accountSettings    AccountSettings
	away               bool
	autoAway           bool
	awayMessage        string
	brbTimer           BrbTimer
	channels           ChannelSet
	ctime              time.Time
	destroyed          bool
	exitedSnomaskSent  bool
	modes              modes.ModeSet
	hostname           string
	invitedTo          StringSet
	isSTSOnly          bool
	languages          []string
	lastActive         time.Time            // last time they sent a command that wasn't PONG or similar
	lastSeen           map[string]time.Time // maps device ID (including "") to time of last received command
	lastSeenLastWrite  time.Time            // last time `lastSeen` was written to the datastore
	loginThrottle      connection_limits.GenericThrottle
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
	registered         bool
	resumeID           string
	server             *Server
	skeleton           string
	sessions           []*Session
	stateMutex         sync.RWMutex // tier 1
	alwaysOn           bool
	username           string
	vhost              string
	history            history.Buffer
	dirtyBits          uint
	writerSemaphore    utils.Semaphore // tier 1.5
}

type saslStatus struct {
	mechanism string
	value     string
}

func (s *saslStatus) Clear() {
	*s = saslStatus{}
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
	lastActive time.Time

	socket      *Socket
	realIP      net.IP
	proxiedIP   net.IP
	rawHostname string
	isTor       bool

	idletimer            IdleTimer
	fakelag              Fakelag
	deferredFakelagCount int
	destroyed            uint32

	certfp     string
	sasl       saslStatus
	passStatus serverPassStatus

	batchCounter uint32

	quitMessage string

	capabilities caps.Set
	capState     caps.State
	capVersion   caps.Version

	registrationMessages int

	resumeID              string
	resumeDetails         *ResumeDetails
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
	fakelagBill := (batch.lenBytes / 512) + 1
	fakelagBillLines := (batch.message.LenLines() * 60) / 512
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
func (sd *Session) SetQuitMessage(message string) (set bool) {
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

// returns whether the session was actively destroyed (for example, by ping
// timeout or NS GHOST).
// avoids a race condition between asynchronous idle-timing-out of sessions,
// and a condition that allows implicit BRB on connection errors (since
// destroy()'s socket.Close() appears to socket.Read() as a connection error)
func (session *Session) Destroyed() bool {
	return atomic.LoadUint32(&session.destroyed) == 1
}

// sets the timed-out flag
func (session *Session) SetDestroyed() {
	atomic.StoreUint32(&session.destroyed, 1)
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
	id := atomic.AddUint32(&session.batchCounter, 1)
	return strconv.FormatInt(int64(id), 32)
}

// WhoWas is the subset of client details needed to answer a WHOWAS query
type WhoWas struct {
	nick           string
	nickCasefolded string
	username       string
	hostname       string
	realname       string
}

// ClientDetails is a standard set of details about a client
type ClientDetails struct {
	WhoWas

	nickMask           string
	nickMaskCasefolded string
	account            string
	accountName        string
}

// RunClient sets up a new client and runs its goroutine.
func (server *Server) RunClient(conn IRCConn) {
	wConn := conn.UnderlyingConn()
	var isBanned bool
	var banMsg string
	realIP := utils.AddrToIP(wConn.RemoteAddr())
	var proxiedIP net.IP
	if wConn.Config.Tor {
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
		isBanned, banMsg = server.checkBans(ipToCheck)
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
	config := server.Config()
	// give them 1k of grace over the limit:
	socket := NewSocket(conn, config.Server.MaxSendQBytes)
	client := &Client{
		lastActive: now,
		channels:   make(ChannelSet),
		ctime:      now,
		isSTSOnly:  wConn.Config.STSOnly,
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
	}
	client.writerSemaphore.Initialize(1)
	client.history.Initialize(config.History.ClientLength, time.Duration(config.History.AutoresizeWindow))
	client.brbTimer.Initialize(client)
	session := &Session{
		client:     client,
		socket:     socket,
		capVersion: caps.Cap301,
		capState:   caps.NoneState,
		ctime:      now,
		lastActive: now,
		realIP:     realIP,
		proxiedIP:  proxiedIP,
		isTor:      wConn.Config.Tor,
	}
	client.sessions = []*Session{session}

	session.idletimer.Initialize(session)
	session.resetFakelag()

	if wConn.Secure {
		client.SetMode(modes.TLS, true)
	}

	if wConn.Config.TLSConfig != nil {
		// error is not useful to us here anyways so we can ignore it
		session.certfp, _ = utils.GetCertFP(wConn.Conn, RegisterTimeout)
	}

	if session.isTor {
		session.rawHostname = config.Server.TorListeners.Vhost
		client.rawHostname = session.rawHostname
	} else {
		if config.Server.CheckIdent {
			client.doIdentLookup(wConn.Conn)
		}
	}

	server.stats.Add()
	client.run(session)
}

func (server *Server) AddAlwaysOnClient(account ClientAccount, chnames []string, lastSeen map[string]time.Time, uModes modes.Modes) {
	now := time.Now().UTC()
	config := server.Config()
	if lastSeen == nil && account.Settings.AutoreplayMissed {
		lastSeen = map[string]time.Time{"": now}
	}

	client := &Client{
		lastSeen:   lastSeen,
		lastActive: now,
		channels:   make(ChannelSet),
		ctime:      now,
		languages:  server.Languages().Default(),
		server:     server,

		// TODO figure out how to set these on reattach?
		username:    "~user",
		rawHostname: server.name,
		realIP:      utils.IPv4LoopbackAddress,

		alwaysOn: true,
	}

	client.SetMode(modes.TLS, true)
	for _, m := range uModes {
		client.SetMode(m, true)
	}
	client.writerSemaphore.Initialize(1)
	client.history.Initialize(0, 0)
	client.brbTimer.Initialize(client)

	server.accounts.Login(client, account)

	client.resizeHistory(config)

	_, err, _ := server.clients.SetNick(client, nil, account.Name)
	if err != nil {
		server.logger.Error("internal", "could not establish always-on client", account.Name, err.Error())
		return
	} else {
		server.logger.Debug("accounts", "established always-on client", account.Name)
	}

	// XXX set this last to avoid confusing SetNick:
	client.registered = true

	for _, chname := range chnames {
		// XXX we're using isSajoin=true, to make these joins succeed even without channel key
		// this is *probably* ok as long as the persisted memberships are accurate
		server.channels.Join(client, chname, "", true, nil)
	}

	if persistenceEnabled(config.Accounts.Multiclient.AutoAway, client.accountSettings.AutoAway) {
		client.autoAway = true
		client.away = true
		client.awayMessage = client.t("User is currently disconnected")
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
	ipString := ip.String()

	var hostname, candidate string
	if config.Server.lookupHostnames {
		session.Notice("*** Looking up your hostname...")

		names, err := net.LookupAddr(ipString)
		if err == nil && 0 < len(names) {
			candidate = strings.TrimSuffix(names[0], ".")
		}
		if utils.IsHostname(candidate) {
			if config.Server.ForwardConfirmHostnames {
				addrs, err := net.LookupHost(candidate)
				if err == nil {
					for _, addr := range addrs {
						if addr == ipString {
							hostname = candidate // successful forward confirmation
							break
						}
					}
				}
			} else {
				hostname = candidate
			}
		}
	}

	if hostname != "" {
		session.Notice("*** Found your hostname")
	} else {
		if config.Server.lookupHostnames {
			session.Notice("*** Couldn't look up your hostname")
		}
		hostname = utils.IPStringToHostname(ipString)
	}

	session.rawHostname = hostname
	cloakedHostname := config.Server.Cloaks.ComputeCloak(ip)
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	// update the hostname if this is a new connection or a resume, but not if it's a reattach
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

func (client *Client) isAuthorized(config *Config, session *Session) AuthOutcome {
	saslSent := client.account != ""
	// PASS requirement
	if (config.Server.passwordBytes != nil) && session.passStatus != serverPassSuccessful && !(config.Accounts.SkipServerPassword && saslSent) {
		return authFailPass
	}
	// Tor connections may be required to authenticate with SASL
	if session.isTor && config.Server.TorListeners.RequireSasl && !saslSent {
		return authFailTorSaslRequired
	}
	// finally, enforce require-sasl
	if config.Accounts.RequireSasl.Enabled && !saslSent && !utils.IPInNets(session.IP(), config.Accounts.RequireSasl.exemptedNets) {
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

	if client.proxiedIP != nil {
		return client.proxiedIP
	}
	return client.realIP
}

// IPString returns the IP address of this client as a string.
func (client *Client) IPString() string {
	ip := client.IP().String()
	if 0 < len(ip) && ip[0] == ':' {
		ip = "0" + ip
	}
	return ip
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
		session.idletimer.Touch()
		if session.resumeDetails != nil {
			session.playResume()
			session.resumeDetails = nil
			client.brbTimer.Disable()
			client.SetAway(false, "") // clear BRB message if any
		} else {
			client.playReattachMessages(session)
		}
	}

	firstLine := !isReattach

	for {
		var invalidUtf8 bool
		line, err := session.socket.Read()
		if err == errInvalidUtf8 {
			invalidUtf8 = true // handle as normal, including labeling
		} else if err != nil {
			quitMessage := "connection closed"
			if err == errReadQ {
				quitMessage = "readQ exceeded"
			}
			client.Quit(quitMessage, session)
			// since the client did not actually send us a QUIT,
			// give them a chance to resume if applicable:
			if !session.Destroyed() {
				client.brbTimer.Enable()
			}
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

		if client.registered {
			touches := session.deferredFakelagCount + 1
			session.deferredFakelagCount = 0
			for i := 0; i < touches; i++ {
				session.fakelag.Touch()
			}
		} else {
			// DoS hardening, #505
			session.registrationMessages++
			if client.server.Config().Limits.RegistrationMessages < session.registrationMessages {
				client.Send(nil, client.server.name, ERR_UNKNOWNERROR, "*", client.t("You have sent too many registration messages"))
				break
			}
		}

		msg, err := ircmsg.ParseLineStrict(line, true, 512)
		if err == ircmsg.ErrorLineIsEmpty {
			continue
		} else if err == ircmsg.ErrorLineTooLong {
			session.Send(nil, client.server.name, ERR_INPUTTOOLONG, client.Nick(), client.t("Input line too long"))
			continue
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
		zncPlayPrivmsgs(client, rb, "*", time.Now().UTC(), session.autoreplayMissedSince)
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
	var markDirty bool
	now := time.Now().UTC()
	client.stateMutex.Lock()
	if client.accountSettings.AutoreplayMissed || session.deviceID != "" {
		client.setLastSeen(now, session.deviceID)
		if now.Sub(client.lastSeenLastWrite) > lastSeenWriteInterval {
			markDirty = true
			client.lastSeenLastWrite = now
		}
	}
	client.stateMutex.Unlock()
	if markDirty {
		client.markDirty(IncludeLastSeen)
	}
}

func (client *Client) setLastSeen(now time.Time, deviceID string) {
	if client.lastSeen == nil {
		client.lastSeen = make(map[string]time.Time)
	}
	client.lastSeen[deviceID] = now
	// evict the least-recently-used entry if necessary
	if maxDeviceIDsPerClient < len(client.lastSeen) {
		var minLastSeen time.Time
		var minClientId string
		for deviceID, lastSeen := range client.lastSeen {
			if minLastSeen.IsZero() || lastSeen.Before(minLastSeen) {
				minClientId, minLastSeen = deviceID, lastSeen
			}
		}
		delete(client.lastSeen, minClientId)
	}
}

// Ping sends the client a PING message.
func (session *Session) Ping() {
	session.Send(nil, "", "PING", session.client.Nick())
}

// tryResume tries to resume if the client asked us to.
func (session *Session) tryResume() (success bool) {
	var oldResumeID string

	defer func() {
		if success {
			// "On a successful request, the server [...] terminates the old client's connection"
			oldSession := session.client.GetSessionByResumeID(oldResumeID)
			if oldSession != nil {
				session.client.destroy(oldSession)
			}
		} else {
			session.resumeDetails = nil
		}
	}()

	client := session.client
	server := client.server
	config := server.Config()

	oldClient, oldResumeID := server.resumeManager.VerifyToken(client, session.resumeDetails.PresentedToken)
	if oldClient == nil {
		session.Send(nil, server.name, "FAIL", "RESUME", "INVALID_TOKEN", client.t("Cannot resume connection, token is not valid"))
		return
	}

	resumeAllowed := config.Server.AllowPlaintextResume || (oldClient.HasMode(modes.TLS) && client.HasMode(modes.TLS))
	if !resumeAllowed {
		session.Send(nil, server.name, "FAIL", "RESUME", "INSECURE_SESSION", client.t("Cannot resume connection, old and new clients must have TLS"))
		return
	}

	err := server.clients.Resume(oldClient, session)
	if err != nil {
		session.Send(nil, server.name, "FAIL", "RESUME", "CANNOT_RESUME", client.t("Cannot resume connection"))
		return
	}

	success = true
	client.server.logger.Debug("quit", fmt.Sprintf("%s is being resumed", oldClient.Nick()))

	return
}

// playResume is called from the session's fresh goroutine after a resume;
// it sends notifications to friends, then plays the registration burst and replays
// stored history to the session
func (session *Session) playResume() {
	client := session.client
	server := client.server
	config := server.Config()

	friends := make(ClientSet)
	var oldestLostMessage time.Time

	// work out how much time, if any, is not covered by history buffers
	// assume that a persistent buffer covers the whole resume period
	for _, channel := range client.Channels() {
		for _, member := range channel.Members() {
			friends.Add(member)
		}
		status, _ := channel.historyStatus(config)
		if status == HistoryEphemeral {
			lastDiscarded := channel.history.LastDiscarded()
			if oldestLostMessage.Before(lastDiscarded) {
				oldestLostMessage = lastDiscarded
			}
		}
	}
	cHistoryStatus, _ := client.historyStatus(config)
	if cHistoryStatus == HistoryEphemeral {
		lastDiscarded := client.history.LastDiscarded()
		if oldestLostMessage.Before(lastDiscarded) {
			oldestLostMessage = lastDiscarded
		}
	}
	_, privmsgSeq, _ := server.GetHistorySequence(nil, client, "*")
	if privmsgSeq != nil {
		privmsgs, _, _ := privmsgSeq.Between(history.Selector{}, history.Selector{}, config.History.ClientLength)
		for _, item := range privmsgs {
			sender := server.clients.Get(stripMaskFromNick(item.Nick))
			if sender != nil {
				friends.Add(sender)
			}
		}
	}

	timestamp := session.resumeDetails.Timestamp
	gap := oldestLostMessage.Sub(timestamp)
	session.resumeDetails.HistoryIncomplete = gap > 0 || timestamp.IsZero()
	gapSeconds := int(gap.Seconds()) + 1 // round up to avoid confusion

	details := client.Details()
	oldNickmask := details.nickMask
	client.lookupHostname(session, true)
	hostname := client.Hostname() // may be a vhost
	timestampString := timestamp.Format(IRCv3TimestampFormat)

	// send quit/resume messages to friends
	for friend := range friends {
		if friend == client {
			continue
		}
		for _, fSession := range friend.Sessions() {
			if fSession.capabilities.Has(caps.Resume) {
				if !session.resumeDetails.HistoryIncomplete {
					fSession.Send(nil, oldNickmask, "RESUMED", hostname, "ok")
				} else if session.resumeDetails.HistoryIncomplete && !timestamp.IsZero() {
					fSession.Send(nil, oldNickmask, "RESUMED", hostname, timestampString)
				} else {
					fSession.Send(nil, oldNickmask, "RESUMED", hostname)
				}
			} else {
				if !session.resumeDetails.HistoryIncomplete {
					fSession.Send(nil, oldNickmask, "QUIT", friend.t("Client reconnected"))
				} else if session.resumeDetails.HistoryIncomplete && !timestamp.IsZero() {
					fSession.Send(nil, oldNickmask, "QUIT", fmt.Sprintf(friend.t("Client reconnected (up to %d seconds of message history lost)"), gapSeconds))
				} else {
					fSession.Send(nil, oldNickmask, "QUIT", friend.t("Client reconnected (message history may have been lost)"))
				}
			}
		}
	}

	if session.resumeDetails.HistoryIncomplete {
		if !timestamp.IsZero() {
			session.Send(nil, client.server.name, "WARN", "RESUME", "HISTORY_LOST", fmt.Sprintf(client.t("Resume may have lost up to %d seconds of history"), gapSeconds))
		} else {
			session.Send(nil, client.server.name, "WARN", "RESUME", "HISTORY_LOST", client.t("Resume may have lost some message history"))
		}
	}

	session.Send(nil, client.server.name, "RESUME", "SUCCESS", details.nick)

	server.playRegistrationBurst(session)

	for _, channel := range client.Channels() {
		channel.Resume(session, timestamp)
	}

	// replay direct PRIVSMG history
	if !timestamp.IsZero() && privmsgSeq != nil {
		after := history.Selector{Time: timestamp}
		items, complete, _ := privmsgSeq.Between(after, history.Selector{}, config.History.ZNCMax)
		if len(items) != 0 {
			rb := NewResponseBuffer(session)
			client.replayPrivmsgHistory(rb, items, "", complete)
			rb.Send(true)
		}
	}

	session.resumeDetails = nil
}

func (client *Client) replayPrivmsgHistory(rb *ResponseBuffer, items []history.Item, target string, complete bool) {
	var batchID string
	details := client.Details()
	nick := details.nick
	if target == "" {
		target = nick
	}
	batchID = rb.StartNestedHistoryBatch(target)

	allowTags := rb.session.capabilities.Has(caps.EventPlayback)
	for _, item := range items {
		var command string
		switch item.Type {
		case history.Privmsg:
			command = "PRIVMSG"
		case history.Notice:
			command = "NOTICE"
		case history.Tagmsg:
			if allowTags {
				command = "TAGMSG"
			} else {
				continue
			}
		default:
			continue
		}
		var tags map[string]string
		if allowTags {
			tags = item.Tags
		}
		// XXX: Params[0] is the message target. if the source of this message is an in-memory
		// buffer, then it's "" for an incoming message and the recipient's nick for an outgoing
		// message. if the source of the message is mysql, then mysql only sees one copy of the
		// message, and it's the version with the recipient's nick filled in. so this is an
		// incoming message if Params[0] (the recipient's nick) equals the client's nick:
		if item.Params[0] == "" || item.Params[0] == nick {
			rb.AddSplitMessageFromClient(item.Nick, item.AccountName, tags, command, nick, item.Message)
		} else {
			// this message was sent *from* the client to another nick; the target is item.Params[0]
			// substitute client's current nickmask in case client changed nick
			rb.AddSplitMessageFromClient(details.nickMask, item.AccountName, tags, command, item.Params[0], item.Message)
		}
	}

	rb.EndNestedBatch(batchID)
	if !complete {
		rb.Add(nil, "HistServ", "NOTICE", nick, client.t("Some additional message history may have been lost"))
	}
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

// HasNick returns true if the client's nickname is set (used in registration).
func (client *Client) HasNick() bool {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.nick != "" && client.nick != "*"
}

// HasUsername returns true if the client's username is set (used in registration).
func (client *Client) HasUsername() bool {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.username != "" && client.username != "*"
}

// SetNames sets the client's ident and realname.
func (client *Client) SetNames(username, realname string, fromIdent bool) error {
	limit := client.server.Config().Limits.IdentLen
	if !fromIdent {
		limit -= 1 // leave room for the prepended ~
	}
	if limit < len(username) {
		username = username[:limit]
	}

	if !isIdent(username) {
		return errInvalidUsername
	}

	if !fromIdent {
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
func (client *Client) Friends(capabs ...caps.Capability) (result map[*Session]bool) {
	result = make(map[*Session]bool)

	// look at the client's own sessions
	for _, session := range client.Sessions() {
		if session.capabilities.HasAll(capabs...) {
			result[session] = true
		}
	}

	for _, channel := range client.Channels() {
		for _, member := range channel.Members() {
			for _, session := range member.Sessions() {
				if session.capabilities.HasAll(capabs...) {
					result[session] = true
				}
			}
		}
	}

	return
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
	for fClient := range client.Friends(caps.ChgHost) {
		fClient.sendFromClientInternal(false, time.Time{}, "", oldNickMask, details.accountName, nil, "CHGHOST", details.username, vhost)
	}
}

// choose the correct vhost to display
func (client *Client) getVHostNoMutex() string {
	// hostserv vhost OR operclass vhost OR nothing (i.e., normal rdns hostmask)
	if client.vhost != "" {
		return client.vhost
	} else if client.oper != nil {
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

// updateNick updates `nick` and `nickCasefolded`.
func (client *Client) updateNick(nick, nickCasefolded, skeleton string) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	client.nick = nick
	client.nickCasefolded = nickCasefolded
	client.skeleton = skeleton
	client.updateNickMaskNoMutex()
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
			finalData, _ = quitMsg.LineBytesStrict(false, 512)
		}

		errorMsg := ircmsg.MakeMessage(nil, "", "ERROR", message)
		errorMsgBytes, _ := errorMsg.LineBytesStrict(false, 512)
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
		if session.SetQuitMessage(message) {
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
	var saveLastSeen bool

	client.stateMutex.Lock()

	details := client.detailsNoMutex()
	brbState := client.brbTimer.state
	brbAt := client.brbTimer.brbAt
	wasReattach := session != nil && session.client != client
	sessionRemoved := false
	registered := client.registered
	alwaysOn := client.alwaysOn

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

	// save last seen if applicable:
	if alwaysOn {
		if client.accountSettings.AutoreplayMissed {
			saveLastSeen = true
		} else {
			for _, session := range sessionsToDestroy {
				if session.deviceID != "" {
					saveLastSeen = true
					break
				}
			}
		}
	}

	// should we destroy the whole client this time?
	// BRB is not respected if this is a destroy of the whole client (i.e., session == nil)
	brbEligible := session != nil && brbState == BrbEnabled
	shouldDestroy := !client.destroyed && remainingSessions == 0 && !brbEligible && !alwaysOn
	// decrement stats on a true destroy, or for the removal of the last connected session
	// of an always-on client
	shouldDecrement := shouldDestroy || (alwaysOn && len(sessionsToDestroy) != 0 && len(client.sessions) == 0)
	if shouldDestroy {
		// if it's our job to destroy it, don't let anyone else try
		client.destroyed = true
	}
	if saveLastSeen {
		client.dirtyBits |= IncludeLastSeen
	}
	exitedSnomaskSent := client.exitedSnomaskSent

	autoAway := false
	var awayMessage string
	if alwaysOn && remainingSessions == 0 && persistenceEnabled(config.Accounts.Multiclient.AutoAway, client.accountSettings.AutoAway) {
		autoAway = true
		client.autoAway = true
		client.away = true
		awayMessage = config.languageManager.Translate(client.languages, `Disconnected from the server`)
		client.awayMessage = awayMessage
	}

	client.stateMutex.Unlock()

	// XXX there is no particular reason to persist this state here rather than
	// any other place: it would be correct to persist it after every `Touch`. However,
	// I'm not comfortable introducing that many database writes, and I don't want to
	// design a throttle.
	if saveLastSeen {
		client.wakeWriter()
	}

	// destroy all applicable sessions:
	var quitMessage string
	for _, session := range sessionsToDestroy {
		if session.client != client {
			// session has been attached to a new client; do not destroy it
			continue
		}
		session.idletimer.Stop()
		// send quit/error message to client if they haven't been sent already
		client.Quit("", session)
		quitMessage = session.quitMessage
		session.SetDestroyed()
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
			client.server.connectionLimiter.RemoveClient(ip)
			source = ip.String()
		}
		client.server.logger.Info("connect-ip", fmt.Sprintf("disconnecting session of %s from %s", details.nick, source))
	}

	// decrement stats if we have no more sessions, even if the client will not be destroyed
	if shouldDecrement {
		invisible := client.HasMode(modes.Invisible)
		operator := client.HasMode(modes.LocalOperator) || client.HasMode(modes.Operator)
		client.server.stats.Remove(registered, invisible, operator)
	}

	if autoAway {
		dispatchAwayNotify(client, true, awayMessage)
	}

	if !shouldDestroy {
		return
	}

	splitQuitMessage := utils.MakeMessage(quitMessage)
	quitItem := history.Item{
		Type:        history.Quit,
		Nick:        details.nickMask,
		AccountName: details.accountName,
		Message:     splitQuitMessage,
	}
	var channels []*Channel
	// use a defer here to avoid writing to mysql while holding the destroy semaphore:
	defer func() {
		for _, channel := range channels {
			channel.AddHistoryItem(quitItem, details.account)
		}
	}()

	// see #235: deduplicating the list of PART recipients uses (comparatively speaking)
	// a lot of RAM, so limit concurrency to avoid thrashing
	client.server.semaphores.ClientDestroy.Acquire()
	defer client.server.semaphores.ClientDestroy.Release()

	if !wasReattach {
		client.server.logger.Debug("quit", fmt.Sprintf("%s is no longer on the server", details.nick))
	}

	if registered {
		client.server.whoWas.Append(client.WhoWas())
	}

	client.server.resumeManager.Delete(client)

	// alert monitors
	if registered {
		client.server.monitorManager.AlertAbout(details.nick, details.nickCasefolded, false)
	}

	// clean up channels
	// (note that if this is a reattach, client has no channels and therefore no friends)
	friends := make(ClientSet)
	channels = client.Channels()
	for _, channel := range channels {
		channel.Quit(client)
		for _, member := range channel.Members() {
			friends.Add(member)
		}
	}
	friends.Remove(client)

	// clean up server
	client.server.clients.Remove(client)

	// clean up self
	client.brbTimer.Disable()

	client.server.accounts.Logout(client)

	// this happens under failure to return from BRB
	if quitMessage == "" {
		if brbState == BrbDead && !brbAt.IsZero() {
			awayMessage := client.AwayMessage()
			if awayMessage == "" {
				awayMessage = "Disconnected" // auto-BRB
			}
			quitMessage = fmt.Sprintf("%s [%s ago]", awayMessage, time.Since(brbAt).Truncate(time.Second).String())
		}
	}
	if quitMessage == "" {
		quitMessage = "Exited"
	}
	for friend := range friends {
		friend.sendFromClientInternal(false, splitQuitMessage.Time, splitQuitMessage.Msgid, details.nickMask, details.accountName, nil, "QUIT", quitMessage)
	}

	if !exitedSnomaskSent && registered {
		client.server.snomasks.Send(sno.LocalQuits, fmt.Sprintf(ircfmt.Unescape("%s$r exited the network"), details.nick))
	}
}

// SendSplitMsgFromClient sends an IRC PRIVMSG/NOTICE coming from a specific client.
// Adds account-tag to the line as well.
func (session *Session) sendSplitMsgFromClientInternal(blocking bool, nickmask, accountName string, tags map[string]string, command, target string, message utils.SplitMessage) {
	if message.Is512() {
		session.sendFromClientInternal(blocking, message.Time, message.Msgid, nickmask, accountName, tags, command, target, message.Message)
	} else {
		if session.capabilities.Has(caps.Multiline) {
			for _, msg := range session.composeMultilineBatch(nickmask, accountName, tags, command, target, message) {
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
				session.sendFromClientInternal(blocking, message.Time, msgid, nickmask, accountName, tags, command, target, messagePair.Message)
			}
		}
	}
}

// Sends a line with `nickmask` as the prefix, adding `time` and `account` tags if supported
func (client *Client) sendFromClientInternal(blocking bool, serverTime time.Time, msgid string, nickmask, accountName string, tags map[string]string, command string, params ...string) (err error) {
	for _, session := range client.Sessions() {
		err_ := session.sendFromClientInternal(blocking, serverTime, msgid, nickmask, accountName, tags, command, params...)
		if err_ != nil {
			err = err_
		}
	}
	return
}

func (session *Session) sendFromClientInternal(blocking bool, serverTime time.Time, msgid string, nickmask, accountName string, tags map[string]string, command string, params ...string) (err error) {
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

	return session.SendRawMessage(msg, blocking)
}

func (session *Session) composeMultilineBatch(fromNickMask, fromAccount string, tags map[string]string, command, target string, message utils.SplitMessage) (result []ircmsg.IrcMessage) {
	batchID := session.generateBatchID()
	batchStart := ircmsg.MakeMessage(tags, fromNickMask, "BATCH", "+"+batchID, caps.MultilineBatchType, target)
	batchStart.SetTag("time", message.Time.Format(IRCv3TimestampFormat))
	batchStart.SetTag("msgid", message.Msgid)
	if session.capabilities.Has(caps.AccountTag) && fromAccount != "*" {
		batchStart.SetTag("account", fromAccount)
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
	// these are all the output commands that MUST have their last param be a trailing.
	// this is needed because dumb clients like to treat trailing params separately from the
	// other params in messages.
	commandsThatMustUseTrailing = map[string]bool{
		"PRIVMSG": true,
		"NOTICE":  true,

		RPL_WHOISCHANNELS: true,
		RPL_USERHOST:      true,

		// mirc's handling of RPL_NAMREPLY is broken:
		// https://forums.mirc.com/ubbthreads.php/topics/266939/re-nick-list
		RPL_NAMREPLY: true,
	}
)

// SendRawMessage sends a raw message to the client.
func (session *Session) SendRawMessage(message ircmsg.IrcMessage, blocking bool) error {
	// use dumb hack to force the last param to be a trailing param if required
	config := session.client.server.Config()
	if config.Server.Compatibility.forceTrailing && commandsThatMustUseTrailing[message.Command] {
		message.ForceTrailing()
	}

	// assemble message
	line, err := message.LineBytesStrict(false, 512)
	if err != nil {
		logline := fmt.Sprintf("Error assembling message for sending: %v\n%s", err, debug.Stack())
		session.client.server.logger.Error("internal", logline)

		message = ircmsg.MakeMessage(nil, session.client.server.name, ERR_UNKNOWNERROR, "*", "Error assembling message for sending")
		line, _ := message.LineBytesStrict(false, 0)

		if blocking {
			session.socket.BlockingWrite(line)
		} else {
			session.socket.Write(line)
		}
		return err
	}

	if session.client.server.logger.IsLoggingRawIO() {
		logline := string(line[:len(line)-2]) // strip "\r\n"
		session.client.server.logger.Debug("useroutput", session.client.Nick(), " ->", logline)
	}

	if blocking {
		return session.socket.BlockingWrite(line)
	} else {
		return session.socket.Write(line)
	}
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

func (session *Session) setTimeTag(msg *ircmsg.IrcMessage, serverTime time.Time) {
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
		client.channels[channel] = empty{} // success
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

// Records that the client has been invited to join an invite-only channel
func (client *Client) Invite(casefoldedChannel string) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	if client.invitedTo == nil {
		client.invitedTo = make(StringSet)
	}

	client.invitedTo.Add(casefoldedChannel)
}

// Checks that the client was invited to join a given channel
func (client *Client) CheckInvited(casefoldedChannel string) (invited bool) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	invited = client.invitedTo.Has(casefoldedChannel)
	// joining an invited channel "uses up" your invite, so you can't rejoin on kick
	delete(client.invitedTo, casefoldedChannel)
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

func (client *Client) copyLastSeen() (result map[string]time.Time) {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	result = make(map[string]time.Time, len(client.lastSeen))
	for id, lastSeen := range client.lastSeen {
		result[id] = lastSeen
	}
	return
}

// these are bit flags indicating what part of the client status is "dirty"
// and needs to be read from memory and written to the db
const (
	IncludeChannels uint = 1 << iota
	IncludeLastSeen
	IncludeUserModes
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
	if client.writerSemaphore.TryAcquire() {
		go client.writeLoop()
	}
}

func (client *Client) writeLoop() {
	for {
		client.performWrite(0)
		client.writerSemaphore.Release()

		client.stateMutex.RLock()
		isDirty := client.dirtyBits != 0
		client.stateMutex.RUnlock()

		if !isDirty || !client.writerSemaphore.TryAcquire() {
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
		channelNames := make([]string, len(channels))
		for i, channel := range channels {
			channelNames[i] = channel.Name()
		}
		client.server.accounts.saveChannels(account, channelNames)
	}
	if (dirtyBits & IncludeLastSeen) != 0 {
		client.server.accounts.saveLastSeen(account, client.copyLastSeen())
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

	client.writerSemaphore.Acquire()
	defer client.writerSemaphore.Release()
	client.performWrite(dirtyBits)
	return nil
}
