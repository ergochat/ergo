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
	OldNick           string
	OldNickMask       string
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
	awayMessage        string
	capabilities       *caps.Set
	capState           caps.State
	capVersion         caps.Version
	certfp             string
	channels           ChannelSet
	ctime              time.Time
	exitedSnomaskSent  bool
	fakelag            *Fakelag
	flags              *modes.ModeSet
	hasQuit            bool
	hops               int
	hostname           string
	idletimer          *IdleTimer
	invitedTo          map[string]bool
	isDestroyed        bool
	isQuitting         bool
	languages          []string
	loginThrottle      connection_limits.GenericThrottle
	maxlenTags         uint32
	maxlenRest         uint32
	nick               string
	nickCasefolded     string
	nickMaskCasefolded string
	nickMaskString     string // cache for nickmask string since it's used with lots of replies
	nickTimer          *NickTimer
	oper               *Oper
	preregNick         string
	proxiedIP          net.IP // actual remote IP if using the PROXY protocol
	quitMessage        string
	rawHostname        string
	realname           string
	realIP             net.IP
	registered         bool
	resumeDetails      *ResumeDetails
	resumeToken        string
	saslInProgress     bool
	saslMechanism      string
	saslValue          string
	sentPassCommand    bool
	server             *Server
	skeleton           string
	socket             *Socket
	stateMutex         sync.RWMutex // tier 1
	username           string
	vhost              string
	history            *history.Buffer
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

// NewClient sets up a new client and starts its goroutine.
func NewClient(server *Server, conn net.Conn, isTLS bool) {
	now := time.Now()
	config := server.Config()
	fullLineLenLimit := config.Limits.LineLen.Tags + config.Limits.LineLen.Rest
	socket := NewSocket(conn, fullLineLenLimit*2, config.Server.MaxSendQBytes)
	client := &Client{
		atime:        now,
		capabilities: caps.NewSet(),
		capState:     caps.NoneState,
		capVersion:   caps.Cap301,
		channels:     make(ChannelSet),
		ctime:        now,
		flags:        modes.NewModeSet(),
		loginThrottle: connection_limits.GenericThrottle{
			Duration: config.Accounts.LoginThrottling.Duration,
			Limit:    config.Accounts.LoginThrottling.MaxAttempts,
		},
		server:         server,
		socket:         socket,
		accountName:    "*",
		nick:           "*", // * is used until actual nick is given
		nickCasefolded: "*",
		nickMaskString: "*", // * is used until actual nick is given
		history:        history.NewHistoryBuffer(config.History.ClientLength),
	}
	client.languages = server.languages.Default()

	remoteAddr := conn.RemoteAddr()
	client.realIP = utils.AddrToIP(remoteAddr)
	if client.realIP == nil {
		server.logger.Error("internal", "bad remote address", remoteAddr.String())
		return
	}
	client.recomputeMaxlens()
	if isTLS {
		client.SetMode(modes.TLS, true)

		// error is not useful to us here anyways so we can ignore it
		client.certfp, _ = client.socket.CertFP()
	}
	if config.Server.CheckIdent && !utils.AddrIsUnix(remoteAddr) {
		_, serverPortString, err := net.SplitHostPort(conn.LocalAddr().String())
		if err != nil {
			server.logger.Error("internal", "bad server address", err.Error())
			return
		}
		serverPort, _ := strconv.Atoi(serverPortString)
		clientHost, clientPortString, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			server.logger.Error("internal", "bad client address", err.Error())
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
	go client.run()
}

func (client *Client) isAuthorized(config *Config) bool {
	saslSent := client.account != ""
	passRequirementMet := (config.Server.passwordBytes == nil) || client.sentPassCommand || (config.Accounts.SkipServerPassword && saslSent)
	if !passRequirementMet {
		return false
	}
	saslRequirementMet := !config.Accounts.RequireSasl.Enabled || saslSent || utils.IPInNets(client.IP(), config.Accounts.RequireSasl.exemptedNets)
	return saslRequirementMet
}

func (client *Client) resetFakelag() {
	fakelag := func() *Fakelag {
		if client.HasRoleCapabs("nofakelag") {
			return nil
		}

		flc := client.server.FakelagConfig()

		if !flc.Enabled {
			return nil
		}

		return NewFakelag(flc.Window, flc.BurstLimit, flc.MessagesPerWindow, flc.Cooldown)
	}()

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	client.fakelag = fakelag
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

func (client *Client) recomputeMaxlens() (int, int) {
	maxlenTags := 512
	maxlenRest := 512
	if client.capabilities.Has(caps.MessageTags) {
		maxlenTags = 4096
	}
	if client.capabilities.Has(caps.MaxLine) {
		limits := client.server.Limits()
		if limits.LineLen.Tags > maxlenTags {
			maxlenTags = limits.LineLen.Tags
		}
		maxlenRest = limits.LineLen.Rest
	}

	atomic.StoreUint32(&client.maxlenTags, uint32(maxlenTags))
	atomic.StoreUint32(&client.maxlenRest, uint32(maxlenRest))

	return maxlenTags, maxlenRest
}

// allow these negotiated length limits to be read without locks; this is a convenience
// so that Client.Send doesn't have to acquire any Client locks
func (client *Client) maxlens() (int, int) {
	return int(atomic.LoadUint32(&client.maxlenTags)), int(atomic.LoadUint32(&client.maxlenRest))
}

func (client *Client) run() {
	var err error
	var isExiting bool
	var line string
	var msg ircmsg.IrcMessage

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
		client.destroy(false)
	}()

	client.idletimer = NewIdleTimer(client)
	client.idletimer.Start()

	client.nickTimer = NewNickTimer(client)

	client.resetFakelag()

	// Set the hostname for this client
	// (may be overridden by a later PROXY command from stunnel)
	client.rawHostname = utils.LookupHostname(client.realIP.String())

	firstLine := true

	for {
		maxlenTags, maxlenRest := client.recomputeMaxlens()

		line, err = client.socket.Read()
		if err != nil {
			quitMessage := "connection closed"
			if err == errReadQ {
				quitMessage = "readQ exceeded"
			}
			client.Quit(quitMessage)
			break
		}

		client.server.logger.Debug("userinput", client.nick, "<- ", line)

		// special-cased handling of PROXY protocol, see `handleProxyCommand` for details:
		if firstLine {
			firstLine = false
			if strings.HasPrefix(line, "PROXY") {
				err = handleProxyCommand(client.server, client, line)
				if err != nil {
					break
				} else {
					continue
				}
			}
		}

		msg, err = ircmsg.ParseLineMaxLen(line, maxlenTags, maxlenRest)
		if err == ircmsg.ErrorLineIsEmpty {
			continue
		} else if err != nil {
			client.Quit(client.t("Received malformed line"))
			break
		}

		cmd, exists := Commands[msg.Command]
		if !exists {
			if len(msg.Command) > 0 {
				client.Send(nil, client.server.name, ERR_UNKNOWNCOMMAND, client.nick, msg.Command, client.t("Unknown command"))
			} else {
				client.Send(nil, client.server.name, ERR_UNKNOWNCOMMAND, client.nick, "lastcmd", client.t("No command given"))
			}
			continue
		}

		isExiting = cmd.Run(client.server, client, msg)
		if isExiting || client.isQuitting {
			break
		}
	}
}

//
// idle, quit, timers and timeouts
//

// Active updates when the client was last 'active' (i.e. the user should be sitting in front of their client).
func (client *Client) Active() {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	client.atime = time.Now()
}

// Ping sends the client a PING message.
func (client *Client) Ping() {
	client.Send(nil, "", "PING", client.nick)

}

// Register sets the client details as appropriate when entering the network.
func (client *Client) Register() {
	client.stateMutex.Lock()
	alreadyRegistered := client.registered
	client.registered = true
	client.stateMutex.Unlock()

	if alreadyRegistered {
		return
	}

	// apply resume details if we're able to.
	client.TryResume()

	// finish registration
	client.updateNickMask()
	client.server.monitorManager.AlertAbout(client, true)
}

// TryResume tries to resume if the client asked us to.
func (client *Client) TryResume() {
	if client.resumeDetails == nil {
		return
	}

	server := client.server
	config := server.Config()

	oldnick := client.resumeDetails.OldNick
	timestamp := client.resumeDetails.Timestamp
	var timestampString string
	if !timestamp.IsZero() {
		timestampString = timestamp.UTC().Format(IRCv3TimestampFormat)
	}

	oldClient := server.clients.Get(oldnick)
	if oldClient == nil {
		client.Send(nil, server.name, "RESUME", "ERR", oldnick, client.t("Cannot resume connection, old client not found"))
		client.resumeDetails = nil
		return
	}
	oldNick := oldClient.Nick()
	oldNickmask := oldClient.NickMaskString()

	resumeAllowed := config.Server.AllowPlaintextResume || (oldClient.HasMode(modes.TLS) && client.HasMode(modes.TLS))
	if !resumeAllowed {
		client.Send(nil, server.name, "RESUME", "ERR", oldnick, client.t("Cannot resume connection, old and new clients must have TLS"))
		client.resumeDetails = nil
		return
	}

	oldResumeToken := oldClient.ResumeToken()
	if oldResumeToken == "" || !utils.SecretTokensMatch(oldResumeToken, client.resumeDetails.PresentedToken) {
		client.Send(nil, server.name, "RESUME", "ERR", client.t("Cannot resume connection, invalid resume token"))
		client.resumeDetails = nil
		return
	}

	err := server.clients.Resume(client, oldClient)
	if err != nil {
		client.resumeDetails = nil
		client.Send(nil, server.name, "RESUME", "ERR", client.t("Cannot resume connection"))
		return
	}

	// this is a bit racey
	client.resumeDetails.ResumedAt = time.Now()

	client.nickTimer.Touch()

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
		return item.Type == history.Privmsg || item.Type == history.Notice
	}
	privmsgHistory := oldClient.history.Match(privmsgMatcher, 0)
	lastDiscarded := oldClient.history.LastDiscarded()
	if lastDiscarded.Before(oldestLostMessage) {
		oldestLostMessage = lastDiscarded
	}
	for _, item := range privmsgHistory {
		// TODO this is the nickmask, fix that
		sender := server.clients.Get(item.Nick)
		if sender != nil {
			friends.Add(sender)
		}
	}

	gap := lastDiscarded.Sub(timestamp)
	client.resumeDetails.HistoryIncomplete = gap > 0
	gapSeconds := int(gap.Seconds()) + 1 // round up to avoid confusion

	// send quit/resume messages to friends
	for friend := range friends {
		if friend.capabilities.Has(caps.Resume) {
			if timestamp.IsZero() {
				friend.Send(nil, oldNickmask, "RESUMED", username, hostname)
			} else {
				friend.Send(nil, oldNickmask, "RESUMED", username, hostname, timestampString)
			}
		} else {
			if client.resumeDetails.HistoryIncomplete {
				friend.Send(nil, oldNickmask, "QUIT", fmt.Sprintf(friend.t("Client reconnected (up to %d seconds of history lost)"), gapSeconds))
			} else {
				friend.Send(nil, oldNickmask, "QUIT", fmt.Sprintf(friend.t("Client reconnected")))
			}
		}
	}

	if client.resumeDetails.HistoryIncomplete {
		client.Send(nil, client.server.name, "RESUME", "WARN", fmt.Sprintf(client.t("Resume may have lost up to %d seconds of history"), gapSeconds))
	}

	client.Send(nil, client.server.name, "RESUME", "SUCCESS", oldNick)

	// after we send the rest of the registration burst, we'll try rejoining channels
}

func (client *Client) tryResumeChannels() {
	details := client.resumeDetails
	if details == nil {
		return
	}

	channels := make([]*Channel, len(details.Channels))
	for _, name := range details.Channels {
		channel := client.server.channels.Get(name)
		if channel == nil {
			continue
		}
		channel.Resume(client, details.OldClient, details.Timestamp)
		channels = append(channels, channel)
	}

	// replay direct PRIVSMG history
	if !details.Timestamp.IsZero() {
		now := time.Now()
		nick := client.Nick()
		items, complete := client.history.Between(details.Timestamp, now)
		for _, item := range items {
			var command string
			switch item.Type {
			case history.Privmsg:
				command = "PRIVMSG"
			case history.Notice:
				command = "NOTICE"
			default:
				continue
			}
			client.sendSplitMsgFromClientInternal(true, item.Time, item.Msgid, item.Nick, item.AccountName, nil, command, nick, item.Message)
		}
		if !complete {
			client.Send(nil, "HistServ", "NOTICE", nick, client.t("Some additional message history may have been lost"))
		}
	}

	details.OldClient.destroy(true)
}

// copy applicable state from oldClient to client as part of a resume
func (client *Client) copyResumeData(oldClient *Client) {
	oldClient.stateMutex.RLock()
	flags := oldClient.flags
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
	temp.Copy(flags)
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
func (client *Client) Friends(capabs ...caps.Capability) ClientSet {
	friends := make(ClientSet)

	// make sure that I have the right caps
	hasCaps := true
	for _, capab := range capabs {
		if !client.capabilities.Has(capab) {
			hasCaps = false
			break
		}
	}
	if hasCaps {
		friends.Add(client)
	}

	for _, channel := range client.Channels() {
		for _, member := range channel.Members() {
			// make sure they have all the required caps
			hasCaps = true
			for _, capab := range capabs {
				if !member.capabilities.Has(capab) {
					hasCaps = false
					break
				}
			}
			if hasCaps {
				friends.Add(member)
			}
		}
	}
	return friends
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

// updateNickMask updates the nickmask.
func (client *Client) updateNickMask() {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
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
	for _, cachedTokenLine := range client.server.ISupport().CachedReply {
		length := len(cachedTokenLine) + 2
		tokenline := make([]string, length)
		tokenline[0] = nick
		copy(tokenline[1:], cachedTokenLine)
		tokenline[length-1] = translatedISupport
		rb.Add(nil, client.server.name, RPL_ISUPPORT, tokenline...)
	}
}

// Quit sets the given quit message for the client and tells the client to quit out.
func (client *Client) Quit(message string) {
	client.stateMutex.Lock()
	alreadyQuit := client.isQuitting
	if !alreadyQuit {
		client.isQuitting = true
		client.quitMessage = message
	}
	client.stateMutex.Unlock()

	if alreadyQuit {
		return
	}

	quitMsg := ircmsg.MakeMessage(nil, client.nickMaskString, "QUIT", message)
	quitLine, _ := quitMsg.Line()

	errorMsg := ircmsg.MakeMessage(nil, "", "ERROR", message)
	errorLine, _ := errorMsg.Line()

	client.socket.SetFinalData(quitLine + errorLine)
}

// destroy gets rid of a client, removes them from server lists etc.
func (client *Client) destroy(beingResumed bool) {
	// allow destroy() to execute at most once
	client.stateMutex.Lock()
	isDestroyed := client.isDestroyed
	client.isDestroyed = true
	quitMessage := client.quitMessage
	nickMaskString := client.nickMaskString
	accountName := client.accountName
	client.stateMutex.Unlock()

	if isDestroyed {
		return
	}

	// see #235: deduplicating the list of PART recipients uses (comparatively speaking)
	// a lot of RAM, so limit concurrency to avoid thrashing
	client.server.semaphores.ClientDestroy.Acquire()
	defer client.server.semaphores.ClientDestroy.Release()

	if beingResumed {
		client.server.logger.Debug("quit", fmt.Sprintf("%s is being resumed", client.nick))
	} else {
		client.server.logger.Debug("quit", fmt.Sprintf("%s is no longer on the server", client.nick))
	}

	// send quit/error message to client if they haven't been sent already
	client.Quit("Connection closed")

	if !beingResumed {
		client.server.whoWas.Append(client.WhoWas())
	}

	// remove from connection limits
	ipaddr := client.IP()
	// this check shouldn't be required but eh
	if ipaddr != nil {
		client.server.connectionLimiter.RemoveClient(ipaddr)
	}

	// alert monitors
	client.server.monitorManager.AlertAbout(client, false)
	// clean up monitor state
	client.server.monitorManager.RemoveAll(client)

	// clean up channels
	friends := make(ClientSet)
	for _, channel := range client.Channels() {
		if !beingResumed {
			channel.Quit(client)
			channel.history.Add(history.Item{
				Type:        history.Quit,
				Nick:        nickMaskString,
				AccountName: accountName,
				Message:     utils.MakeSplitMessage(quitMessage, true),
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
	client.idletimer.Stop()
	client.nickTimer.Stop()

	client.server.accounts.Logout(client)

	client.socket.Close()

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
			friend.Send(nil, client.nickMaskString, "QUIT", quitMessage)
		}
	}
	if !client.exitedSnomaskSent {
		if beingResumed {
			client.server.snomasks.Send(sno.LocalQuits, fmt.Sprintf(ircfmt.Unescape("%s$r is resuming their connection, old client has been destroyed"), client.nick))
		} else {
			client.server.snomasks.Send(sno.LocalQuits, fmt.Sprintf(ircfmt.Unescape("%s$r exited the network"), client.nick))
		}
	}
}

// SendSplitMsgFromClient sends an IRC PRIVMSG/NOTICE coming from a specific client.
// Adds account-tag to the line as well.
func (client *Client) SendSplitMsgFromClient(msgid string, from *Client, tags Tags, command, target string, message utils.SplitMessage) {
	client.sendSplitMsgFromClientInternal(false, time.Time{}, msgid, from.NickMaskString(), from.AccountName(), tags, command, target, message)
}

func (client *Client) sendSplitMsgFromClientInternal(blocking bool, serverTime time.Time, msgid string, nickmask, accountName string, tags Tags, command, target string, message utils.SplitMessage) {
	if client.capabilities.Has(caps.MaxLine) || message.Wrapped == nil {
		client.sendFromClientInternal(blocking, serverTime, msgid, nickmask, accountName, tags, command, target, message.Original)
	} else {
		for _, str := range message.Wrapped {
			client.sendFromClientInternal(blocking, serverTime, msgid, nickmask, accountName, tags, command, target, str)
		}
	}
}

// SendFromClient sends an IRC line coming from a specific client.
// Adds account-tag to the line as well.
func (client *Client) SendFromClient(msgid string, from *Client, tags Tags, command string, params ...string) error {
	return client.sendFromClientInternal(false, time.Time{}, msgid, from.NickMaskString(), from.AccountName(), tags, command, params...)
}

// helper to add a tag to `tags` (or create a new tag set if the current one is nil)
func ensureTag(tags Tags, tagName, tagValue string) (result Tags) {
	if tags == nil {
		result = ircmsg.MakeTags(tagName, tagValue)
	} else {
		result = tags
		(*tags)[tagName] = ircmsg.MakeTagValue(tagValue)
	}
	return
}

// XXX this is a hack where we allow overriding the client's nickmask
// this is to support CHGHOST, which requires that we send the *original* nickmask with the response
func (client *Client) sendFromClientInternal(blocking bool, serverTime time.Time, msgid string, nickmask, accountName string, tags Tags, command string, params ...string) error {
	// attach account-tag
	if client.capabilities.Has(caps.AccountTag) && accountName != "*" {
		tags = ensureTag(tags, "account", accountName)
	}
	// attach message-id
	if len(msgid) > 0 && client.capabilities.Has(caps.MessageTags) {
		tags = ensureTag(tags, "draft/msgid", msgid)
	}

	return client.sendInternal(blocking, serverTime, tags, nickmask, command, params...)
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
func (client *Client) SendRawMessage(message ircmsg.IrcMessage, blocking bool) error {
	// use dumb hack to force the last param to be a trailing param if required
	var usedTrailingHack bool
	if commandsThatMustUseTrailing[strings.ToUpper(message.Command)] && len(message.Params) > 0 {
		lastParam := message.Params[len(message.Params)-1]
		// to force trailing, we ensure the final param contains a space
		if !strings.Contains(lastParam, " ") {
			message.Params[len(message.Params)-1] = lastParam + " "
			usedTrailingHack = true
		}
	}

	// assemble message
	maxlenTags, maxlenRest := client.maxlens()
	line, err := message.LineMaxLenBytes(maxlenTags, maxlenRest)
	if err != nil {
		logline := fmt.Sprintf("Error assembling message for sending: %v\n%s", err, debug.Stack())
		client.server.logger.Error("internal", logline)

		message = ircmsg.MakeMessage(nil, client.server.name, ERR_UNKNOWNERROR, "*", "Error assembling message for sending")
		line, _ := message.LineBytes()

		if blocking {
			client.socket.BlockingWrite(line)
		} else {
			client.socket.Write(line)
		}
		return err
	}

	// if we used the trailing hack, we need to strip the final space we appended earlier on
	if usedTrailingHack {
		copy(line[len(line)-3:], []byte{'\r', '\n'})
		line = line[:len(line)-1]
	}

	if client.server.logger.IsLoggingRawIO() {
		logline := string(line[:len(line)-2]) // strip "\r\n"
		client.server.logger.Debug("useroutput", client.nick, " ->", logline)
	}

	if blocking {
		return client.socket.BlockingWrite(line)
	} else {
		return client.socket.Write(line)
	}
}

func (client *Client) sendInternal(blocking bool, serverTime time.Time, tags Tags, prefix string, command string, params ...string) error {
	// attach server time
	if client.capabilities.Has(caps.ServerTime) {
		if serverTime.IsZero() {
			serverTime = time.Now()
		}
		tags = ensureTag(tags, "time", serverTime.UTC().Format(IRCv3TimestampFormat))
	}

	// send out the message
	message := ircmsg.MakeMessage(tags, prefix, command, params...)
	client.SendRawMessage(message, blocking)
	return nil
}

// Send sends an IRC line to the client.
func (client *Client) Send(tags Tags, prefix string, command string, params ...string) error {
	return client.sendInternal(false, time.Time{}, tags, prefix, command, params...)
}

// Notice sends the client a notice from the server.
func (client *Client) Notice(text string) {
	limit := 400
	if client.capabilities.Has(caps.MaxLine) {
		limit = client.server.Limits().LineLen.Rest - 110
	}
	lines := utils.WordWrap(text, limit)

	// force blank lines to be sent if we receive them
	if len(lines) == 0 {
		lines = []string{""}
	}

	for _, line := range lines {
		client.Send(nil, client.server.name, "NOTICE", client.nick, line)
	}
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

// Ensures the client has a cryptographically secure resume token, and returns
// its value. An error is returned if a token was previously assigned.
func (client *Client) generateResumeToken() (token string, err error) {
	newToken := utils.GenerateSecretToken()

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	if client.resumeToken == "" {
		client.resumeToken = newToken
	} else {
		err = errResumeTokenAlreadySet
	}

	return client.resumeToken, err
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
