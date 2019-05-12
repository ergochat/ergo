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
	OldClient         *Client
	PresentedToken    string
	Timestamp         time.Time
	ResumedAt         time.Time
	Channels          []string
	HistoryIncomplete bool
}

// Client is an IRC client.
type Client struct {
	account            string
	accountName        string // display name of the account: uncasefolded, '*' if not logged in
	atime              time.Time
	away               bool
	awayMessage        string
	certfp             string
	channels           ChannelSet
	ctime              time.Time
	exitedSnomaskSent  bool
	flags              modes.ModeSet
	hostname           string
	invitedTo          map[string]bool
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
	realname           string
	realIP             net.IP
	registered         bool
	resumeDetails      *ResumeDetails
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
	history            *history.Buffer
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

	quitMessage string

	capabilities caps.Set
	maxlenRest   uint32
	capState     caps.State
	capVersion   caps.Version
}

// sets the session quit message, if there isn't one already
func (sd *Session) SetQuitMessage(message string) (set bool) {
	if message == "" {
		if sd.quitMessage == "" {
			sd.quitMessage = "Connection closed"
			return true
		} else {
			return false
		}
	} else {
		sd.quitMessage = message
		return true
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

// NewClient sets up a new client and runs its goroutine.
func RunNewClient(server *Server, conn clientConn) {
	now := time.Now()
	config := server.Config()
	fullLineLenLimit := ircmsg.MaxlenTagsFromClient + config.Limits.LineLen.Rest
	// give them 1k of grace over the limit:
	socket := NewSocket(conn.Conn, fullLineLenLimit+1024, config.Server.MaxSendQBytes)
	client := &Client{
		atime:     now,
		channels:  make(ChannelSet),
		ctime:     now,
		isTor:     conn.IsTor,
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
		history:        history.NewHistoryBuffer(config.History.ClientLength),
	}
	session := &Session{
		client:     client,
		socket:     socket,
		capVersion: caps.Cap301,
		capState:   caps.NoneState,
		ctime:      now,
		atime:      now,
	}
	session.SetMaxlenRest()
	client.sessions = []*Session{session}

	if conn.IsTLS {
		client.SetMode(modes.TLS, true)
		// error is not useful to us here anyways so we can ignore it
		client.certfp, _ = socket.CertFP()
	}

	remoteAddr := conn.Conn.RemoteAddr()
	if conn.IsTor {
		client.SetMode(modes.TLS, true)
		session.realIP = utils.AddrToIP(remoteAddr)
		// cover up details of the tor proxying infrastructure (not a user privacy concern,
		// but a hardening measure):
		session.proxiedIP = utils.IPv4LoopbackAddress
		session.rawHostname = config.Server.TorListeners.Vhost
	} else {
		session.realIP = utils.AddrToIP(remoteAddr)
		// set the hostname for this client (may be overridden later by PROXY or WEBIRC)
		session.rawHostname = utils.LookupHostname(session.realIP.String())
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

	client.run(session)
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

func (client *Client) isAuthorized(config *Config) bool {
	saslSent := client.account != ""
	// PASS requirement
	if (config.Server.passwordBytes != nil) && !client.sentPassCommand && !(config.Accounts.SkipServerPassword && saslSent) {
		return false
	}
	// Tor connections may be required to authenticate with SASL
	if client.isTor && config.Server.TorListeners.RequireSasl && !saslSent {
		return false
	}
	// finally, enforce require-sasl
	return !config.Accounts.RequireSasl.Enabled || saslSent || utils.IPInNets(client.IP(), config.Accounts.RequireSasl.exemptedNets)
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

//
// command goroutine
//

func (client *Client) run(session *Session) {

	defer func() {
		if r := recover(); r != nil {
			client.server.logger.Error("internal",
				fmt.Sprintf("Client caused panic: %v\n%s", r, debug.Stack()))
			if client.server.RecoverFromErrors() {
				client.server.logger.Error("internal", "Disconnecting client and attempting to recover")
			} else {
				panic(r)
			}
		}
		// ensure client connection gets closed
		client.destroy(false, session)
	}()

	session.idletimer.Initialize(session)
	session.resetFakelag()

	isReattach := client.Registered()
	if isReattach {
		client.playReattachMessages(session)
	} else {
		// don't reset the nick timer during a reattach
		client.nickTimer.Initialize(client)
	}

	firstLine := true

	for {
		maxlenRest := session.MaxlenRest()

		line, err := session.socket.Read()
		if err != nil {
			quitMessage := "connection closed"
			if err == errReadQ {
				quitMessage = "readQ exceeded"
			}
			client.Quit(quitMessage, session)
			break
		}

		if client.server.logger.IsLoggingRawIO() {
			client.server.logger.Debug("userinput", client.nick, "<- ", line)
		}

		// special-cased handling of PROXY protocol, see `handleProxyCommand` for details:
		if !isReattach && firstLine {
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

		msg, err := ircmsg.ParseLineStrict(line, true, maxlenRest)
		if err == ircmsg.ErrorLineIsEmpty {
			continue
		} else if err == ircmsg.ErrorLineTooLong {
			client.Send(nil, client.server.name, ERR_INPUTTOOLONG, client.Nick(), client.t("Input line too long"))
			continue
		} else if err != nil {
			client.Quit(client.t("Received malformed line"), session)
			break
		}

		cmd, exists := Commands[msg.Command]
		if !exists {
			if len(msg.Command) > 0 {
				client.Send(nil, client.server.name, ERR_UNKNOWNCOMMAND, client.Nick(), msg.Command, client.t("Unknown command"))
			} else {
				client.Send(nil, client.server.name, ERR_UNKNOWNCOMMAND, client.Nick(), "lastcmd", client.t("No command given"))
			}
			continue
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
	for _, channel := range session.client.Channels() {
		channel.playJoinForSession(session)
	}
}

//
// idle, quit, timers and timeouts
//

// Active updates when the client was last 'active' (i.e. the user should be sitting in front of their client).
func (client *Client) Active(session *Session) {
	// TODO normalize all times to utc?
	now := time.Now()
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
func (client *Client) tryResume() (success bool) {
	server := client.server
	config := server.Config()

	defer func() {
		if !success {
			client.resumeDetails = nil
		}
	}()

	timestamp := client.resumeDetails.Timestamp
	var timestampString string
	if !timestamp.IsZero() {
		timestampString = timestamp.UTC().Format(IRCv3TimestampFormat)
	}

	oldClient := server.resumeManager.VerifyToken(client.resumeDetails.PresentedToken)
	if oldClient == nil {
		client.Send(nil, server.name, "RESUME", "ERR", client.t("Cannot resume connection, token is not valid"))
		return
	}
	oldNick := oldClient.Nick()
	oldNickmask := oldClient.NickMaskString()

	resumeAllowed := config.Server.AllowPlaintextResume || (oldClient.HasMode(modes.TLS) && client.HasMode(modes.TLS))
	if !resumeAllowed {
		client.Send(nil, server.name, "RESUME", "ERR", client.t("Cannot resume connection, old and new clients must have TLS"))
		return
	}

	if oldClient.isTor != client.isTor {
		client.Send(nil, server.name, "RESUME", "ERR", client.t("Cannot resume connection from Tor to non-Tor or vice versa"))
		return
	}

	if 1 < len(oldClient.Sessions()) {
		client.Send(nil, server.name, "RESUME", "ERR", client.t("Cannot resume a client with multiple attached sessions"))
		return
	}

	err := server.clients.Resume(client, oldClient)
	if err != nil {
		client.Send(nil, server.name, "RESUME", "ERR", client.t("Cannot resume connection"))
		return
	}

	success = true

	// this is a bit racey
	client.resumeDetails.ResumedAt = time.Now()

	client.nickTimer.Touch(nil)

	// resume successful, proceed to copy client state (nickname, flags, etc.)
	// after this, the server thinks that `newClient` owns the nickname

	client.resumeDetails.OldClient = oldClient

	// transfer monitor stuff
	server.monitorManager.Resume(client, oldClient)

	// record the names, not the pointers, of the channels,
	// to avoid dumb annoying race conditions
	channels := oldClient.Channels()
	client.resumeDetails.Channels = make([]string, len(channels))
	for i, channel := range channels {
		client.resumeDetails.Channels[i] = channel.Name()
	}

	username := client.Username()
	hostname := client.Hostname()

	friends := make(ClientSet)
	oldestLostMessage := time.Now()

	// work out how much time, if any, is not covered by history buffers
	for _, channel := range channels {
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
	privmsgHistory := oldClient.history.Match(privmsgMatcher, false, 0)
	lastDiscarded := oldClient.history.LastDiscarded()
	if lastDiscarded.Before(oldestLostMessage) {
		oldestLostMessage = lastDiscarded
	}
	for _, item := range privmsgHistory {
		sender := server.clients.Get(stripMaskFromNick(item.Nick))
		if sender != nil {
			friends.Add(sender)
		}
	}

	gap := lastDiscarded.Sub(timestamp)
	client.resumeDetails.HistoryIncomplete = gap > 0
	gapSeconds := int(gap.Seconds()) + 1 // round up to avoid confusion

	// send quit/resume messages to friends
	for friend := range friends {
		for _, session := range friend.Sessions() {
			if session.capabilities.Has(caps.Resume) {
				if timestamp.IsZero() {
					session.Send(nil, oldNickmask, "RESUMED", username, hostname)
				} else {
					session.Send(nil, oldNickmask, "RESUMED", username, hostname, timestampString)
				}
			} else {
				if client.resumeDetails.HistoryIncomplete {
					session.Send(nil, oldNickmask, "QUIT", fmt.Sprintf(friend.t("Client reconnected (up to %d seconds of history lost)"), gapSeconds))
				} else {
					session.Send(nil, oldNickmask, "QUIT", fmt.Sprintf(friend.t("Client reconnected")))
				}
			}
		}
	}

	if client.resumeDetails.HistoryIncomplete {
		client.Send(nil, client.server.name, "RESUME", "WARN", fmt.Sprintf(client.t("Resume may have lost up to %d seconds of history"), gapSeconds))
	}

	client.Send(nil, client.server.name, "RESUME", "SUCCESS", oldNick)

	// after we send the rest of the registration burst, we'll try rejoining channels
	return
}

func (client *Client) tryResumeChannels() {
	details := client.resumeDetails

	for _, name := range details.Channels {
		channel := client.server.channels.Get(name)
		if channel == nil {
			continue
		}
		channel.Resume(client, details.OldClient, details.Timestamp)
	}

	// replay direct PRIVSMG history
	if !details.Timestamp.IsZero() {
		now := time.Now()
		items, complete := client.history.Between(details.Timestamp, now, false, 0)
		rb := NewResponseBuffer(client.Sessions()[0])
		client.replayPrivmsgHistory(rb, items, complete)
		rb.Send(true)
	}

	details.OldClient.destroy(true, nil)
}

func (client *Client) replayPrivmsgHistory(rb *ResponseBuffer, items []history.Item, complete bool) {
	var batchID string
	nick := client.Nick()
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
		rb.AddSplitMessageFromClient(item.Nick, item.AccountName, tags, command, nick, item.Message)
	}

	rb.EndNestedBatch(batchID)
	if !complete {
		rb.Add(nil, "HistServ", "NOTICE", nick, client.t("Some additional message history may have been lost"))
	}
}

// copy applicable state from oldClient to client as part of a resume
func (client *Client) copyResumeData(oldClient *Client) {
	oldClient.stateMutex.RLock()
	history := oldClient.history
	nick := oldClient.nick
	nickCasefolded := oldClient.nickCasefolded
	vhost := oldClient.vhost
	account := oldClient.account
	accountName := oldClient.accountName
	skeleton := oldClient.skeleton
	oldClient.stateMutex.RUnlock()

	// copy all flags, *except* TLS (in the case that the admins enabled
	// resume over plaintext)
	hasTLS := client.flags.HasMode(modes.TLS)
	temp := modes.NewModeSet()
	temp.Copy(&oldClient.flags)
	temp.SetMode(modes.TLS, hasTLS)
	client.flags.Copy(temp)

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	// reuse the old client's history buffer
	client.history = history
	// copy other data
	client.nick = nick
	client.nickCasefolded = nickCasefolded
	client.vhost = vhost
	client.account = account
	client.accountName = accountName
	client.skeleton = skeleton
	client.updateNickMaskNoMutex()
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
		client.hostname = client.rawHostname
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

// RplISupport outputs our ISUPPORT lines to the client. This is used on connection and in VERSION responses.
func (client *Client) RplISupport(rb *ResponseBuffer) {
	translatedISupport := client.t("are supported by this server")
	nick := client.Nick()
	config := client.server.Config()
	for _, cachedTokenLine := range config.Server.isupport.CachedReply {
		length := len(cachedTokenLine) + 2
		tokenline := make([]string, length)
		tokenline[0] = nick
		copy(tokenline[1:], cachedTokenLine)
		tokenline[length-1] = translatedISupport
		rb.Add(nil, client.server.name, RPL_ISUPPORT, tokenline...)
	}
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
func (client *Client) destroy(beingResumed bool, session *Session) {
	var sessionsToDestroy []*Session

	// allow destroy() to execute at most once
	client.stateMutex.Lock()
	details := client.detailsNoMutex()
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
	client.stateMutex.Unlock()

	if len(sessionsToDestroy) == 0 {
		return
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

	// ok, now destroy the client, unless it still has sessions:
	if remainingSessions != 0 {
		return
	}

	// see #235: deduplicating the list of PART recipients uses (comparatively speaking)
	// a lot of RAM, so limit concurrency to avoid thrashing
	client.server.semaphores.ClientDestroy.Acquire()
	defer client.server.semaphores.ClientDestroy.Release()

	if beingResumed {
		client.server.logger.Debug("quit", fmt.Sprintf("%s is being resumed", details.nick))
	} else if !wasReattach {
		client.server.logger.Debug("quit", fmt.Sprintf("%s is no longer on the server", details.nick))
	}

	registered := client.Registered()
	if !beingResumed && registered {
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
		if !beingResumed {
			channel.Quit(client)
			channel.history.Add(history.Item{
				Type:        history.Quit,
				Nick:        details.nickMask,
				AccountName: details.accountName,
				Message:     splitQuitMessage,
			})
		}
		for _, member := range channel.Members() {
			friends.Add(member)
		}
	}
	friends.Remove(client)

	// clean up server
	if !beingResumed {
		client.server.clients.Remove(client)
	}

	// clean up self
	client.nickTimer.Stop()

	client.server.accounts.Logout(client)

	// send quit messages to friends
	if !beingResumed {
		if client.Registered() {
			client.server.stats.ChangeTotal(-1)
		}
		if client.HasMode(modes.Invisible) {
			client.server.stats.ChangeInvisible(-1)
		}
		if client.HasMode(modes.Operator) || client.HasMode(modes.LocalOperator) {
			client.server.stats.ChangeOperators(-1)
		}

		for friend := range friends {
			if quitMessage == "" {
				quitMessage = "Exited"
			}
			friend.sendFromClientInternal(false, splitQuitMessage.Time, splitQuitMessage.Msgid, details.nickMask, details.accountName, nil, "QUIT", quitMessage)
		}
	}
	if !client.exitedSnomaskSent {
		if beingResumed {
			client.server.snomasks.Send(sno.LocalQuits, fmt.Sprintf(ircfmt.Unescape("%s$r is resuming their connection, old client has been destroyed"), client.nick))
		} else {
			client.server.snomasks.Send(sno.LocalQuits, fmt.Sprintf(ircfmt.Unescape("%s$r exited the network"), details.nick))
		}
	}
}

// SendSplitMsgFromClient sends an IRC PRIVMSG/NOTICE coming from a specific client.
// Adds account-tag to the line as well.
func (session *Session) sendSplitMsgFromClientInternal(blocking bool, serverTime time.Time, nickmask, accountName string, tags map[string]string, command, target string, message utils.SplitMessage) {
	if session.capabilities.Has(caps.MaxLine) || message.Wrapped == nil {
		session.sendFromClientInternal(blocking, serverTime, message.Msgid, nickmask, accountName, tags, command, target, message.Message)
	} else {
		for _, messagePair := range message.Wrapped {
			session.sendFromClientInternal(blocking, serverTime, messagePair.Msgid, nickmask, accountName, tags, command, target, messagePair.Message)
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
		msg.SetTag("draft/msgid", msgid)
	}
	// attach server-time
	if session.capabilities.Has(caps.ServerTime) {
		if serverTime.IsZero() {
			serverTime = time.Now().UTC()
		}
		msg.SetTag("time", serverTime.Format(IRCv3TimestampFormat))
	}

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
	if session.capabilities.Has(caps.ServerTime) && !msg.HasTag("time") {
		msg.SetTag("time", time.Now().UTC().Format(IRCv3TimestampFormat))
	}
	return session.SendRawMessage(msg, false)
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
