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
	// IdentTimeoutSeconds is how many seconds before our ident (username) check times out.
	IdentTimeoutSeconds  = 1.5
	IRCv3TimestampFormat = "2006-01-02T15:04:05.000Z"
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
	accountSettings    AccountSettings
	atime              time.Time
	away               bool
	awayMessage        string
	brbTimer           BrbTimer
	certfp             string
	channels           ChannelSet
	ctime              time.Time
	destroyed          bool
	exitedSnomaskSent  bool
	flags              modes.ModeSet
	hostname           string
	invitedTo          map[string]bool
	isSTSOnly          bool
	isTor              bool
	languages          []string
	loginThrottle      connection_limits.GenericThrottle
	nick               string
	nickCasefolded     string
	nickMaskCasefolded string
	nickMaskString     string // cache for nickmask string since it's used with lots of replies
	nickTimer          NickTimer
	oper               *Oper
	preregNick         string
	proxiedIP          net.IP // actual remote IP if using the PROXY protocol
	rawHostname        string
	cloakedHostname    string
	realname           string
	realIP             net.IP
	registered         bool
	resumeID           string
	saslInProgress     bool
	saslMechanism      string
	saslValue          string
	sentPassCommand    bool
	server             *Server
	skeleton           string
	sessions           []*Session
	stateMutex         sync.RWMutex // tier 1
	username           string
	vhost              string
	history            history.Buffer
}

// Session is an individual client connection to the server (TCP connection
// and associated per-connection data, such as capabilities). There is a
// many-one relationship between sessions and clients.
type Session struct {
	client *Client

	ctime time.Time
	atime time.Time

	socket      *Socket
	realIP      net.IP
	proxiedIP   net.IP
	rawHostname string

	idletimer IdleTimer
	fakelag   Fakelag
	destroyed uint32

	quitMessage string

	capabilities caps.Set
	maxlenRest   uint32
	capState     caps.State
	capVersion   caps.Version

	registrationMessages int

	resumeID         string
	resumeDetails    *ResumeDetails
	zncPlaybackTimes *zncPlaybackTimes
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

// set the negotiated message length based on session capabilities
func (session *Session) SetMaxlenRest() {
	maxlenRest := 512
	if session.capabilities.Has(caps.MaxLine) {
		maxlenRest = session.client.server.Config().Limits.LineLen.Rest
	}
	atomic.StoreUint32(&session.maxlenRest, uint32(maxlenRest))
}

// allow the negotiated message length limit to be read without locks; this is a convenience
// so that Session.SendRawMessage doesn't have to acquire any Client locks
func (session *Session) MaxlenRest() int {
	return int(atomic.LoadUint32(&session.maxlenRest))
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
	// TODO the chathistory cap will go here as well
	return session.capabilities.Has(caps.ZNCPlayback)
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
func (server *Server) RunClient(conn clientConn, proxyLine string) {
	var isBanned bool
	var banMsg string
	var realIP net.IP
	if conn.Config.Tor {
		realIP = utils.IPv4LoopbackAddress
		isBanned, banMsg = server.checkTorLimits()
	} else {
		realIP = utils.AddrToIP(conn.Conn.RemoteAddr())
		isBanned, banMsg = server.checkBans(realIP)
	}

	if isBanned {
		// this might not show up properly on some clients,
		// but our objective here is just to close the connection out before it has a load impact on us
		conn.Conn.Write([]byte(fmt.Sprintf(errorMsg, banMsg)))
		conn.Conn.Close()
		return
	}

	server.logger.Info("localconnect-ip", fmt.Sprintf("Client connecting from %v", realIP))

	now := time.Now().UTC()
	config := server.Config()
	fullLineLenLimit := ircmsg.MaxlenTagsFromClient + config.Limits.LineLen.Rest
	// give them 1k of grace over the limit:
	socket := NewSocket(conn.Conn, fullLineLenLimit+1024, config.Server.MaxSendQBytes)
	client := &Client{
		atime:     now,
		channels:  make(ChannelSet),
		ctime:     now,
		isSTSOnly: conn.Config.STSOnly,
		isTor:     conn.Config.Tor,
		languages: server.Languages().Default(),
		loginThrottle: connection_limits.GenericThrottle{
			Duration: config.Accounts.LoginThrottling.Duration,
			Limit:    config.Accounts.LoginThrottling.MaxAttempts,
		},
		server:         server,
		accountName:    "*",
		nick:           "*", // * is used until actual nick is given
		nickCasefolded: "*",
		nickMaskString: "*", // * is used until actual nick is given
	}
	client.history.Initialize(config.History.ClientLength, config.History.AutoresizeWindow)
	client.brbTimer.Initialize(client)
	session := &Session{
		client:     client,
		socket:     socket,
		capVersion: caps.Cap301,
		capState:   caps.NoneState,
		ctime:      now,
		atime:      now,
		realIP:     realIP,
	}
	session.SetMaxlenRest()
	client.sessions = []*Session{session}

	if conn.Config.TLSConfig != nil {
		client.SetMode(modes.TLS, true)
		// error is not useful to us here anyways so we can ignore it
		client.certfp, _ = socket.CertFP()
	}

	if conn.Config.Tor {
		client.SetMode(modes.TLS, true)
		// cover up details of the tor proxying infrastructure (not a user privacy concern,
		// but a hardening measure):
		session.proxiedIP = utils.IPv4LoopbackAddress
		session.rawHostname = config.Server.TorListeners.Vhost
	} else {
		// set the hostname for this client (may be overridden later by PROXY or WEBIRC)
		session.rawHostname = utils.LookupHostname(session.realIP.String())
		client.cloakedHostname = config.Server.Cloaks.ComputeCloak(session.realIP)
		remoteAddr := conn.Conn.RemoteAddr()
		if utils.AddrIsLocal(remoteAddr) {
			// treat local connections as secure (may be overridden later by WEBIRC)
			client.SetMode(modes.TLS, true)
		}
		if config.Server.CheckIdent && !utils.AddrIsUnix(remoteAddr) {
			client.doIdentLookup(conn.Conn)
		}
	}
	client.realIP = session.realIP
	client.rawHostname = session.rawHostname
	client.proxiedIP = session.proxiedIP

	server.stats.Add()
	client.run(session, proxyLine)
}

func (client *Client) doIdentLookup(conn net.Conn) {
	_, serverPortString, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		client.server.logger.Error("internal", "bad server address", err.Error())
		return
	}
	serverPort, _ := strconv.Atoi(serverPortString)
	clientHost, clientPortString, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		client.server.logger.Error("internal", "bad client address", err.Error())
		return
	}
	clientPort, _ := strconv.Atoi(clientPortString)

	client.Notice(client.t("*** Looking up your username"))
	resp, err := ident.Query(clientHost, serverPort, clientPort, IdentTimeoutSeconds)
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

func (client *Client) isAuthorized(config *Config) AuthOutcome {
	saslSent := client.account != ""
	// PASS requirement
	if (config.Server.passwordBytes != nil) && !client.sentPassCommand && !(config.Accounts.SkipServerPassword && saslSent) {
		return authFailPass
	}
	// Tor connections may be required to authenticate with SASL
	if client.isTor && config.Server.TorListeners.RequireSasl && !saslSent {
		return authFailTorSaslRequired
	}
	// finally, enforce require-sasl
	if config.Accounts.RequireSasl.Enabled && !saslSent && !utils.IPInNets(client.IP(), config.Accounts.RequireSasl.exemptedNets) {
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
func (client *Client) run(session *Session, proxyLine string) {

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

	session.idletimer.Initialize(session)
	session.resetFakelag()

	isReattach := client.Registered()
	if isReattach {
		if session.resumeDetails != nil {
			session.playResume()
			session.resumeDetails = nil
			client.brbTimer.Disable()
			client.SetAway(false, "") // clear BRB message if any
		} else {
			client.playReattachMessages(session)
		}
	} else {
		// don't reset the nick timer during a reattach
		client.nickTimer.Initialize(client)
	}

	firstLine := !isReattach

	for {
		maxlenRest := session.MaxlenRest()

		var line string
		var err error
		if proxyLine == "" {
			line, err = session.socket.Read()
		} else {
			line = proxyLine // pretend we're just now receiving the proxy-before-TLS line
			proxyLine = ""
		}
		if err != nil {
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
			session.fakelag.Touch()
		} else {
			// DoS hardening, #505
			session.registrationMessages++
			if client.server.Config().Limits.RegistrationMessages < session.registrationMessages {
				client.Send(nil, client.server.name, ERR_UNKNOWNERROR, "*", client.t("You have sent too many registration messages"))
				break
			}
		}

		msg, err := ircmsg.ParseLineStrict(line, true, maxlenRest)
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
			if len(msg.Command) > 0 {
				session.Send(nil, client.server.name, ERR_UNKNOWNCOMMAND, client.Nick(), msg.Command, client.t("Unknown command"))
			} else {
				session.Send(nil, client.server.name, ERR_UNKNOWNCOMMAND, client.Nick(), "lastcmd", client.t("No command given"))
			}
			continue
		}

		isExiting := cmd.Run(client.server, client, session, msg)
		if isExiting {
			break
		} else if session.client != client {
			// bouncer reattach
			go session.client.run(session, "")
			break
		}
	}
}

func (client *Client) playReattachMessages(session *Session) {
	client.server.playRegistrationBurst(session)
	for _, channel := range session.client.Channels() {
		channel.playJoinForSession(session)
		// clients should receive autoreplay-on-join lines, if applicable;
		// if they negotiated znc.in/playback or chathistory, they will receive nothing,
		// because those caps disable autoreplay-on-join and they haven't sent the relevant
		// *playback PRIVMSG or CHATHISTORY command yet
		rb := NewResponseBuffer(session)
		channel.autoReplayHistory(client, rb, "")
		rb.Send(true)
	}
}

//
// idle, quit, timers and timeouts
//

// Active updates when the client was last 'active' (i.e. the user should be sitting in front of their client).
func (client *Client) Active(session *Session) {
	now := time.Now().UTC()
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	session.atime = now
	client.atime = now
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

	if oldClient.isTor != client.isTor {
		session.Send(nil, server.name, "FAIL", "RESUME", "INSECURE_SESSION", client.t("Cannot resume connection from Tor to non-Tor or vice versa"))
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

	friends := make(ClientSet)
	oldestLostMessage := time.Now().UTC()

	// work out how much time, if any, is not covered by history buffers
	for _, channel := range client.Channels() {
		for _, member := range channel.Members() {
			friends.Add(member)
			lastDiscarded := channel.history.LastDiscarded()
			if lastDiscarded.Before(oldestLostMessage) {
				oldestLostMessage = lastDiscarded
			}
		}
	}
	privmsgMatcher := func(item history.Item) bool {
		return item.Type == history.Privmsg || item.Type == history.Notice || item.Type == history.Tagmsg
	}
	privmsgHistory := client.history.Match(privmsgMatcher, false, 0)
	lastDiscarded := client.history.LastDiscarded()
	if lastDiscarded.Before(oldestLostMessage) {
		oldestLostMessage = lastDiscarded
	}
	for _, item := range privmsgHistory {
		sender := server.clients.Get(stripMaskFromNick(item.Nick))
		if sender != nil {
			friends.Add(sender)
		}
	}

	timestamp := session.resumeDetails.Timestamp
	gap := lastDiscarded.Sub(timestamp)
	session.resumeDetails.HistoryIncomplete = gap > 0 || timestamp.IsZero()
	gapSeconds := int(gap.Seconds()) + 1 // round up to avoid confusion

	details := client.Details()
	oldNickmask := details.nickMask
	client.SetRawHostname(session.rawHostname)
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

	if session.resumeDetails.HistoryIncomplete && !timestamp.IsZero() {
		session.Send(nil, client.server.name, "WARN", "RESUME", "HISTORY_LOST", fmt.Sprintf(client.t("Resume may have lost up to %d seconds of history"), gapSeconds))
	} else {
		session.Send(nil, client.server.name, "WARN", "RESUME", "HISTORY_LOST", client.t("Resume may have lost some message history"))
	}

	session.Send(nil, client.server.name, "RESUME", "SUCCESS", details.nick)

	server.playRegistrationBurst(session)

	for _, channel := range client.Channels() {
		channel.Resume(session, timestamp)
	}

	// replay direct PRIVSMG history
	if !timestamp.IsZero() {
		now := time.Now().UTC()
		items, complete := client.history.Between(timestamp, now, false, 0)
		rb := NewResponseBuffer(client.Sessions()[0])
		client.replayPrivmsgHistory(rb, items, complete)
		rb.Send(true)
	}

	session.resumeDetails = nil
}

func (client *Client) replayPrivmsgHistory(rb *ResponseBuffer, items []history.Item, complete bool) {
	var batchID string
	details := client.Details()
	nick := details.nick
	if 0 < len(items) {
		batchID = rb.StartNestedHistoryBatch(nick)
	}

	allowTags := rb.session.capabilities.Has(caps.MessageTags)
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
		if item.Params[0] == "" {
			// this message was sent *to* the client from another nick
			rb.AddSplitMessageFromClient(item.Nick, item.AccountName, tags, command, nick, item.Message)
		} else {
			// this message was sent *from* the client to another nick; the target is item.Params[0]
			// substitute the client's current nickmask in case they changed nick
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
	return time.Since(client.atime)
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
		if !oper.Class.Capabilities[capab] {
			return false
		}
	}

	return true
}

// ModeString returns the mode string for this client.
func (client *Client) ModeString() (str string) {
	return "+" + client.flags.String()
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
	username := client.Username()
	for fClient := range client.Friends(caps.ChgHost) {
		fClient.sendFromClientInternal(false, time.Time{}, "", oldNickMask, client.AccountName(), nil, "CHGHOST", username, vhost)
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
	client.hostname = client.getVHostNoMutex()
	if client.hostname == "" {
		client.hostname = client.cloakedHostname
		if client.hostname == "" {
			client.hostname = client.rawHostname
		}
	}

	cfhostname, err := Casefold(client.hostname)
	if err != nil {
		client.server.logger.Error("internal", "hostname couldn't be casefolded", client.hostname, err.Error())
		cfhostname = client.hostname // YOLO
	}

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
		cfvhost, err := Casefold(vhost)
		if err == nil {
			masks = append(masks, fmt.Sprintf("%s!%s@%s", nick, username, cfvhost))
		}
	}

	var rawhostmask string
	cfrawhost, err := Casefold(rawHostname)
	if err == nil {
		rawhostmask = fmt.Sprintf("%s!%s@%s", nick, username, cfrawhost)
		masks = append(masks, rawhostmask)
	}

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
	var sessionsToDestroy []*Session

	client.stateMutex.Lock()
	details := client.detailsNoMutex()
	brbState := client.brbTimer.state
	brbAt := client.brbTimer.brbAt
	wasReattach := session != nil && session.client != client
	sessionRemoved := false
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
	// BRB is not respected if this is a destroy of the whole client (i.e., session == nil)
	brbEligible := session != nil && (brbState == BrbEnabled || brbState == BrbSticky)
	shouldDestroy := !client.destroyed && remainingSessions == 0 && !brbEligible
	if shouldDestroy {
		// if it's our job to destroy it, don't let anyone else try
		client.destroyed = true
	}
	exitedSnomaskSent := client.exitedSnomaskSent
	client.stateMutex.Unlock()

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

		// remove from connection limits
		var source string
		if client.isTor {
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
		client.server.logger.Info("localconnect-ip", fmt.Sprintf("disconnecting session of %s from %s", details.nick, source))
	}

	// do not destroy the client if it has either remaining sessions, or is BRB'ed
	if !shouldDestroy {
		return
	}

	// see #235: deduplicating the list of PART recipients uses (comparatively speaking)
	// a lot of RAM, so limit concurrency to avoid thrashing
	client.server.semaphores.ClientDestroy.Acquire()
	defer client.server.semaphores.ClientDestroy.Release()

	if !wasReattach {
		client.server.logger.Debug("quit", fmt.Sprintf("%s is no longer on the server", details.nick))
	}

	registered := client.Registered()
	if registered {
		client.server.whoWas.Append(client.WhoWas())
	}

	client.server.resumeManager.Delete(client)

	// alert monitors
	if registered {
		client.server.monitorManager.AlertAbout(client, false)
	}
	// clean up monitor state
	client.server.monitorManager.RemoveAll(client)

	splitQuitMessage := utils.MakeSplitMessage(quitMessage, true)
	// clean up channels
	// (note that if this is a reattach, client has no channels and therefore no friends)
	friends := make(ClientSet)
	for _, channel := range client.Channels() {
		channel.Quit(client)
		channel.history.Add(history.Item{
			Type:        history.Quit,
			Nick:        details.nickMask,
			AccountName: details.accountName,
			Message:     splitQuitMessage,
		})
		for _, member := range channel.Members() {
			friends.Add(member)
		}
	}
	friends.Remove(client)

	// clean up server
	client.server.clients.Remove(client)

	// clean up self
	client.nickTimer.Stop()
	client.brbTimer.Disable()

	client.server.accounts.Logout(client)

	client.server.stats.Remove(registered, client.HasMode(modes.Invisible),
		client.HasMode(modes.Operator) || client.HasMode(modes.LocalOperator))

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
	if session.capabilities.Has(caps.MaxLine) || message.Wrapped == nil {
		session.sendFromClientInternal(blocking, message.Time, message.Msgid, nickmask, accountName, tags, command, target, message.Message)
	} else {
		for _, messagePair := range message.Wrapped {
			session.sendFromClientInternal(blocking, message.Time, messagePair.Msgid, nickmask, accountName, tags, command, target, messagePair.Message)
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

var (
	// these are all the output commands that MUST have their last param be a trailing.
	// this is needed because dumb clients like to treat trailing params separately from the
	// other params in messages.
	commandsThatMustUseTrailing = map[string]bool{
		"PRIVMSG": true,
		"NOTICE":  true,

		RPL_WHOISCHANNELS: true,
		RPL_USERHOST:      true,
	}
)

// SendRawMessage sends a raw message to the client.
func (session *Session) SendRawMessage(message ircmsg.IrcMessage, blocking bool) error {
	// use dumb hack to force the last param to be a trailing param if required
	var usedTrailingHack bool
	config := session.client.server.Config()
	if config.Server.Compatibility.forceTrailing && commandsThatMustUseTrailing[message.Command] && len(message.Params) > 0 {
		lastParam := message.Params[len(message.Params)-1]
		// to force trailing, we ensure the final param contains a space
		if strings.IndexByte(lastParam, ' ') == -1 {
			message.Params[len(message.Params)-1] = lastParam + " "
			usedTrailingHack = true
		}
	}

	// assemble message
	maxlenRest := session.MaxlenRest()
	line, err := message.LineBytesStrict(false, maxlenRest)
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

	// if we used the trailing hack, we need to strip the final space we appended earlier on
	if usedTrailingHack {
		copy(line[len(line)-3:], "\r\n")
		line = line[:len(line)-1]
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

func (client *Client) addChannel(channel *Channel) {
	client.stateMutex.Lock()
	client.channels[channel] = true
	client.stateMutex.Unlock()
}

func (client *Client) removeChannel(channel *Channel) {
	client.stateMutex.Lock()
	delete(client.channels, channel)
	client.stateMutex.Unlock()
}

// Records that the client has been invited to join an invite-only channel
func (client *Client) Invite(casefoldedChannel string) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	if client.invitedTo == nil {
		client.invitedTo = make(map[string]bool)
	}

	client.invitedTo[casefoldedChannel] = true
}

// Checks that the client was invited to join a given channel
func (client *Client) CheckInvited(casefoldedChannel string) (invited bool) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	invited = client.invitedTo[casefoldedChannel]
	// joining an invited channel "uses up" your invite, so you can't rejoin on kick
	delete(client.invitedTo, casefoldedChannel)
	return
}
