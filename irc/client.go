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
	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/sno"
	"github.com/oragono/oragono/irc/utils"
)

const (
	// IdentTimeoutSeconds is how many seconds before our ident (username) check times out.
	IdentTimeoutSeconds = 1.5
)

var (
	LoopbackIP = net.ParseIP("127.0.0.1")
)

// Client is an IRC client.
type Client struct {
	account            string
	accountName        string
	atime              time.Time
	authorized         bool
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
	isDestroyed        bool
	isQuitting         bool
	languages          []string
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
	registered         bool
	resumeDetails      *ResumeDetails
	saslInProgress     bool
	saslMechanism      string
	saslValue          string
	server             *Server
	socket             *Socket
	stateMutex         sync.RWMutex // tier 1
	username           string
	vhost              string
}

// NewClient sets up a new client and starts its goroutine.
func NewClient(server *Server, conn net.Conn, isTLS bool) {
	now := time.Now()
	config := server.Config()
	fullLineLenLimit := config.Limits.LineLen.Tags + config.Limits.LineLen.Rest
	socket := NewSocket(conn, fullLineLenLimit*2, config.Server.MaxSendQBytes)
	client := &Client{
		atime:          now,
		authorized:     server.Password() == nil,
		capabilities:   caps.NewSet(),
		capState:       caps.NoneState,
		capVersion:     caps.Cap301,
		channels:       make(ChannelSet),
		ctime:          now,
		flags:          modes.NewModeSet(),
		server:         server,
		socket:         socket,
		nick:           "*", // * is used until actual nick is given
		nickCasefolded: "*",
		nickMaskString: "*", // * is used until actual nick is given
	}
	client.languages = server.languages.Default()

	client.recomputeMaxlens()
	if isTLS {
		client.SetMode(modes.TLS, true)

		// error is not useful to us here anyways so we can ignore it
		client.certfp, _ = client.socket.CertFP()
	}
	if config.Server.CheckIdent && !utils.AddrIsUnix(conn.RemoteAddr()) {
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
			username := resp.Identifier
			_, err := CasefoldName(username) // ensure it's a valid username
			if err == nil {
				client.Notice(client.t("*** Found your username"))
				client.username = username
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
	if client.proxiedIP != nil {
		return client.proxiedIP
	}
	if ip := utils.AddrToIP(client.socket.conn.RemoteAddr()); ip != nil {
		return ip
	}
	// unix domain socket that hasn't issued PROXY/WEBIRC yet. YOLO
	return LoopbackIP
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
	client.rawHostname = utils.AddrLookupHostname(client.socket.conn.RemoteAddr())

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

		client.server.logger.Debug("userinput ", client.nick, "<- ", line)

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

// Touch marks the client as alive (as it it has a connection to us and we
// can receive messages from it).
func (client *Client) Touch() {
	client.idletimer.Touch()
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
	client.updateNickMask("")
	client.server.monitorManager.AlertAbout(client, true)
}

// TryResume tries to resume if the client asked us to.
func (client *Client) TryResume() {
	if client.resumeDetails == nil {
		return
	}

	server := client.server

	// just grab these mutexes for safety. later we can work out whether we can grab+release them earlier
	server.clients.Lock()
	defer server.clients.Unlock()
	server.channels.Lock()
	defer server.channels.Unlock()

	oldnick := client.resumeDetails.OldNick
	timestamp := client.resumeDetails.Timestamp
	var timestampString string
	if timestamp != nil {
		timestampString = timestamp.UTC().Format("2006-01-02T15:04:05.999Z")
	}

	// can't use server.clients.Get since we hold server.clients' tier 1 mutex
	casefoldedName, err := CasefoldName(oldnick)
	if err != nil {
		client.Send(nil, server.name, ERR_CANNOT_RESUME, oldnick, client.t("Cannot resume connection, old client not found"))
		return
	}

	oldClient := server.clients.byNick[casefoldedName]
	if oldClient == nil {
		client.Send(nil, server.name, ERR_CANNOT_RESUME, oldnick, client.t("Cannot resume connection, old client not found"))
		return
	}

	oldAccountName := oldClient.Account()
	newAccountName := client.Account()

	if oldAccountName == "" || newAccountName == "" || oldAccountName != newAccountName {
		client.Send(nil, server.name, ERR_CANNOT_RESUME, oldnick, client.t("Cannot resume connection, old and new clients must be logged into the same account"))
		return
	}

	if !oldClient.HasMode(modes.TLS) || !client.HasMode(modes.TLS) {
		client.Send(nil, server.name, ERR_CANNOT_RESUME, oldnick, client.t("Cannot resume connection, old and new clients must have TLS"))
		return
	}

	// unmark the new client's nick as being occupied
	server.clients.removeInternal(client)

	// send RESUMED to the reconnecting client
	if timestamp == nil {
		client.Send(nil, oldClient.NickMaskString(), "RESUMED", oldClient.nick, client.username, client.Hostname())
	} else {
		client.Send(nil, oldClient.NickMaskString(), "RESUMED", oldClient.nick, client.username, client.Hostname(), timestampString)
	}

	// send QUIT/RESUMED to friends
	for friend := range oldClient.Friends() {
		if friend.capabilities.Has(caps.Resume) {
			if timestamp == nil {
				friend.Send(nil, oldClient.NickMaskString(), "RESUMED", oldClient.nick, client.username, client.Hostname())
			} else {
				friend.Send(nil, oldClient.NickMaskString(), "RESUMED", oldClient.nick, client.username, client.Hostname(), timestampString)
			}
		} else {
			friend.Send(nil, oldClient.NickMaskString(), "QUIT", friend.t("Client reconnected"))
		}
	}

	// apply old client's details to new client
	client.nick = oldClient.nick
	client.updateNickMaskNoMutex()

	rejoinChannel := func(channel *Channel) {
		channel.joinPartMutex.Lock()
		defer channel.joinPartMutex.Unlock()

		channel.stateMutex.Lock()
		client.channels[channel] = true
		client.resumeDetails.SendFakeJoinsFor = append(client.resumeDetails.SendFakeJoinsFor, channel.name)

		oldModeSet := channel.members[oldClient]
		channel.members.Remove(oldClient)
		channel.members[client] = oldModeSet
		channel.stateMutex.Unlock()

		channel.regenerateMembersCache()

		// construct fake modestring if necessary
		oldModes := oldModeSet.String()
		var params []string
		if 0 < len(oldModes) {
			params = []string{channel.name, "+" + oldModes}
			for range oldModes {
				params = append(params, client.nick)
			}
		}

		// send join for old clients
		for member := range channel.members {
			if member.capabilities.Has(caps.Resume) {
				continue
			}

			if member.capabilities.Has(caps.ExtendedJoin) {
				member.Send(nil, client.nickMaskString, "JOIN", channel.name, client.AccountName(), client.realname)
			} else {
				member.Send(nil, client.nickMaskString, "JOIN", channel.name)
			}

			// send fake modestring if necessary
			if 0 < len(oldModes) {
				member.Send(nil, server.name, "MODE", params...)
			}
		}
	}

	for channel := range oldClient.channels {
		rejoinChannel(channel)
	}

	server.clients.byNick[oldnick] = client

	oldClient.destroy(true)
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

// XXX: CHGHOST requires prefix nickmask to have original hostname,
// this is annoying to do correctly
func (client *Client) sendChghost(oldNickMask string, vhost string) {
	username := client.Username()
	for fClient := range client.Friends(caps.ChgHost) {
		fClient.sendFromClientInternal("", client, oldNickMask, nil, "CHGHOST", username, vhost)
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
func (client *Client) updateNick(nick string) {
	casefoldedName, err := CasefoldName(nick)
	if err != nil {
		client.server.logger.Error("internal", "nick couldn't be casefolded", nick, err.Error())
		return
	}
	client.stateMutex.Lock()
	client.nick = nick
	client.nickCasefolded = casefoldedName
	client.stateMutex.Unlock()
}

// updateNickMask updates the casefolded nickname and nickmask.
func (client *Client) updateNickMask(nick string) {
	// on "", just regenerate the nickmask etc.
	// otherwise, update the actual nick
	if nick != "" {
		client.updateNick(nick)
	}

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	client.updateNickMaskNoMutex()
}

// updateNickMask updates the casefolded nickname and nickmask, not acquiring any mutexes.
func (client *Client) updateNickMaskNoMutex() {
	client.hostname = client.getVHostNoMutex()
	if client.hostname == "" {
		client.hostname = client.rawHostname
	}

	nickMaskString := fmt.Sprintf("%s!%s@%s", client.nick, client.username, client.hostname)
	nickMaskCasefolded, err := Casefold(nickMaskString)
	if err != nil {
		client.server.logger.Error("internal", "nickmask couldn't be casefolded", nickMaskString, err.Error())
		return
	}

	client.nickMaskString = nickMaskString
	client.nickMaskCasefolded = nickMaskCasefolded
}

// AllNickmasks returns all the possible nickmasks for the client.
func (client *Client) AllNickmasks() []string {
	var masks []string
	var mask string
	var err error

	client.stateMutex.RLock()
	nick := client.nick
	username := client.username
	rawHostname := client.rawHostname
	vhost := client.getVHostNoMutex()
	client.stateMutex.RUnlock()

	if len(vhost) > 0 {
		mask, err = Casefold(fmt.Sprintf("%s!%s@%s", nick, username, vhost))
		if err == nil {
			masks = append(masks, mask)
		}
	}

	mask, err = Casefold(fmt.Sprintf("%s!%s@%s", nick, username, rawHostname))
	if err == nil {
		masks = append(masks, mask)
	}

	mask2, err := Casefold(fmt.Sprintf("%s!%s@%s", nick, username, client.IPString()))
	if err == nil && mask2 != mask {
		masks = append(masks, mask2)
	}

	return masks
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
	if !beingResumed {
		client.stateMutex.Lock()
	}
	isDestroyed := client.isDestroyed
	client.isDestroyed = true
	if !beingResumed {
		client.stateMutex.Unlock()
	}
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
		client.server.stats.ChangeTotal(-1)
		if client.HasMode(modes.Invisible) {
			client.server.stats.ChangeInvisible(-1)
		}

		if client.HasMode(modes.Operator) || client.HasMode(modes.LocalOperator) {
			client.server.stats.ChangeOperators(-1)
		}

		for friend := range friends {
			if client.quitMessage == "" {
				client.quitMessage = "Exited"
			}
			friend.Send(nil, client.nickMaskString, "QUIT", client.quitMessage)
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
func (client *Client) SendSplitMsgFromClient(msgid string, from *Client, tags *map[string]ircmsg.TagValue, command, target string, message SplitMessage) {
	if client.capabilities.Has(caps.MaxLine) {
		client.SendFromClient(msgid, from, tags, command, target, message.ForMaxLine)
	} else {
		for _, str := range message.For512 {
			client.SendFromClient(msgid, from, tags, command, target, str)
		}
	}
}

// SendFromClient sends an IRC line coming from a specific client.
// Adds account-tag to the line as well.
func (client *Client) SendFromClient(msgid string, from *Client, tags *map[string]ircmsg.TagValue, command string, params ...string) error {
	return client.sendFromClientInternal(msgid, from, from.NickMaskString(), tags, command, params...)
}

// XXX this is a hack where we allow overriding the client's nickmask
// this is to support CHGHOST, which requires that we send the *original* nickmask with the response
func (client *Client) sendFromClientInternal(msgid string, from *Client, nickmask string, tags *map[string]ircmsg.TagValue, command string, params ...string) error {
	// attach account-tag
	if client.capabilities.Has(caps.AccountTag) && from.LoggedIntoAccount() {
		if tags == nil {
			tags = ircmsg.MakeTags("account", from.AccountName())
		} else {
			(*tags)["account"] = ircmsg.MakeTagValue(from.AccountName())
		}
	}
	// attach message-id
	if len(msgid) > 0 && client.capabilities.Has(caps.MessageTags) {
		if tags == nil {
			tags = ircmsg.MakeTags("draft/msgid", msgid)
		} else {
			(*tags)["draft/msgid"] = ircmsg.MakeTagValue(msgid)
		}
	}

	return client.Send(tags, nickmask, command, params...)
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
func (client *Client) SendRawMessage(message ircmsg.IrcMessage) error {
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

		client.socket.Write(line)
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

	client.socket.Write(line)

	return nil
}

// Send sends an IRC line to the client.
func (client *Client) Send(tags *map[string]ircmsg.TagValue, prefix string, command string, params ...string) error {
	// attach server-time
	if client.capabilities.Has(caps.ServerTime) {
		t := time.Now().UTC().Format("2006-01-02T15:04:05.999Z")
		if tags == nil {
			tags = ircmsg.MakeTags("time", t)
		} else {
			(*tags)["time"] = ircmsg.MakeTagValue(t)
		}
	}

	// send out the message
	message := ircmsg.MakeMessage(tags, prefix, command, params...)
	client.SendRawMessage(message)
	return nil
}

// Notice sends the client a notice from the server.
func (client *Client) Notice(text string) {
	limit := 400
	if client.capabilities.Has(caps.MaxLine) {
		limit = client.server.Limits().LineLen.Rest - 110
	}
	lines := wordWrap(text, limit)

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
