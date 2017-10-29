// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"log"
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
	"github.com/oragono/oragono/irc/sno"
	"github.com/oragono/oragono/irc/utils"
)

const (
	// IdentTimeoutSeconds is how many seconds before our ident (username) check times out.
	IdentTimeoutSeconds = 1.5
)

var (
	// ErrNickAlreadySet is a weird error that's sent when the server's consistency has been compromised.
	ErrNickAlreadySet = errors.New("Nickname is already set")
)

// Client is an IRC client.
type Client struct {
	account            *ClientAccount
	atime              time.Time
	authorized         bool
	awayMessage        string
	capabilities       *caps.Set
	capState           CapState
	capVersion         caps.Version
	certfp             string
	channels           ChannelSet
	class              *OperClass
	ctime              time.Time
	exitedSnomaskSent  bool
	flags              map[Mode]bool
	hasQuit            bool
	hops               int
	hostname           string
	idletimer          *IdleTimer
	isDestroyed        bool
	isQuitting         bool
	maxlenTags         uint32
	maxlenRest         uint32
	nick               string
	nickCasefolded     string
	nickMaskCasefolded string
	nickMaskString     string // cache for nickmask string since it's used with lots of replies
	operName           string
	proxiedIP          string // actual remote IP if using the PROXY protocol
	quitMessage        string
	rawHostname        string
	realname           string
	registered         bool
	saslInProgress     bool
	saslMechanism      string
	saslValue          string
	server             *Server
	socket             *Socket
	stateMutex         sync.RWMutex // generic protection for mutable state
	username           string
	vhost              string
	whoisLine          string
}

// NewClient returns a client with all the appropriate info setup.
func NewClient(server *Server, conn net.Conn, isTLS bool) *Client {
	now := time.Now()
	socket := NewSocket(conn, server.MaxSendQBytes)
	go socket.RunSocketWriter()
	client := &Client{
		atime:          now,
		authorized:     server.getPassword() == nil,
		capabilities:   caps.NewSet(),
		capState:       CapNone,
		capVersion:     caps.Cap301,
		channels:       make(ChannelSet),
		ctime:          now,
		flags:          make(map[Mode]bool),
		server:         server,
		socket:         &socket,
		account:        &NoAccount,
		nick:           "*", // * is used until actual nick is given
		nickCasefolded: "*",
		nickMaskString: "*", // * is used until actual nick is given
	}
	if isTLS {
		client.flags[TLS] = true

		// error is not useful to us here anyways so we can ignore it
		client.certfp, _ = client.socket.CertFP()
	}
	if server.checkIdent {
		_, serverPortString, err := net.SplitHostPort(conn.LocalAddr().String())
		serverPort, _ := strconv.Atoi(serverPortString)
		if err != nil {
			log.Fatal(err)
		}
		clientHost, clientPortString, err := net.SplitHostPort(conn.RemoteAddr().String())
		clientPort, _ := strconv.Atoi(clientPortString)
		if err != nil {
			log.Fatal(err)
		}

		client.Notice("*** Looking up your username")
		resp, err := ident.Query(clientHost, serverPort, clientPort, IdentTimeoutSeconds)
		if err == nil {
			username := resp.Identifier
			_, err := CasefoldName(username) // ensure it's a valid username
			if err == nil {
				client.Notice("*** Found your username")
				client.username = username
				// we don't need to updateNickMask here since nickMask is not used for anything yet
			} else {
				client.Notice("*** Got a malformed username, ignoring")
			}
		} else {
			client.Notice("*** Could not find your username")
		}
	}
	go client.run()

	return client
}

// IP returns the IP address of this client.
func (client *Client) IP() net.IP {
	if client.proxiedIP != "" {
		return net.ParseIP(client.proxiedIP)
	}

	return net.ParseIP(utils.IPString(client.socket.conn.RemoteAddr()))
}

// IPString returns the IP address of this client as a string.
func (client *Client) IPString() string {
	if client.proxiedIP != "" {
		return client.proxiedIP
	}

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
		limits := client.server.getLimits()
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
		client.destroy()
	}()

	client.idletimer = NewIdleTimer(client)
	client.idletimer.Start()

	// Set the hostname for this client
	// (may be overridden by a later PROXY command from stunnel)
	client.rawHostname = utils.AddrLookupHostname(client.socket.conn.RemoteAddr())

	for {
		maxlenTags, maxlenRest := client.recomputeMaxlens()

		line, err = client.socket.Read()
		if err != nil {
			client.Quit("connection closed")
			break
		}

		client.server.logger.Debug("userinput ", client.nick, "<- ", line)

		msg, err = ircmsg.ParseLineMaxLen(line, maxlenTags, maxlenRest)
		if err == ircmsg.ErrorLineIsEmpty {
			continue
		} else if err != nil {
			client.Quit("received malformed line")
			break
		}

		cmd, exists := Commands[msg.Command]
		if !exists {
			if len(msg.Command) > 0 {
				client.Send(nil, client.server.name, ERR_UNKNOWNCOMMAND, client.nick, msg.Command, "Unknown command")
			} else {
				client.Send(nil, client.server.name, ERR_UNKNOWNCOMMAND, client.nick, "lastcmd", "No command given")
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

//
// server goroutine
//

// Register sets the client details as appropriate when entering the network.
func (client *Client) Register() {
	client.stateMutex.Lock()
	alreadyRegistered := client.registered
	client.registered = true
	client.stateMutex.Unlock()

	if alreadyRegistered {
		return
	}

	client.Touch()
	client.updateNickMask("")
	client.server.monitorManager.AlertAbout(client, true)
}

// IdleTime returns how long this client's been idle.
func (client *Client) IdleTime() time.Duration {
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
	return client.nick != "" && client.nick != "*"
}

// HasUsername returns true if the client's username is set (used in registration).
func (client *Client) HasUsername() bool {
	return client.username != "" && client.username != "*"
}

// HasRoleCapabs returns true if client has the given (role) capabilities.
func (client *Client) HasRoleCapabs(capabs ...string) bool {
	if client.class == nil {
		return false
	}

	for _, capab := range capabs {
		if !client.class.Capabilities[capab] {
			return false
		}
	}

	return true
}

// ModeString returns the mode string for this client.
func (client *Client) ModeString() (str string) {
	str = "+"

	for flag := range client.flags {
		str += flag.String()
	}

	return
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

// updateNick updates `nick` and `nickCasefolded`.
func (client *Client) updateNick(nick string) {
	casefoldedName, err := CasefoldName(nick)
	if err != nil {
		log.Println(fmt.Sprintf("ERROR: Nick [%s] couldn't be casefolded... this should never happen. Printing stacktrace.", client.nick))
		debug.PrintStack()
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

	if len(client.vhost) > 0 {
		client.hostname = client.vhost
	} else {
		client.hostname = client.rawHostname
	}

	nickMaskString := fmt.Sprintf("%s!%s@%s", client.nick, client.username, client.hostname)
	nickMaskCasefolded, err := Casefold(nickMaskString)
	if err != nil {
		log.Println(fmt.Sprintf("ERROR: Nickmask [%s] couldn't be casefolded... this should never happen. Printing stacktrace.", client.nickMaskString))
		debug.PrintStack()
	}

	client.nickMaskString = nickMaskString
	client.nickMaskCasefolded = nickMaskCasefolded

	client.stateMutex.Unlock()
}

// AllNickmasks returns all the possible nickmasks for the client.
func (client *Client) AllNickmasks() []string {
	var masks []string
	var mask string
	var err error

	if len(client.vhost) > 0 {
		mask, err = Casefold(fmt.Sprintf("%s!%s@%s", client.nick, client.username, client.vhost))
		if err == nil {
			masks = append(masks, mask)
		}
	}

	mask, err = Casefold(fmt.Sprintf("%s!%s@%s", client.nick, client.username, client.rawHostname))
	if err == nil {
		masks = append(masks, mask)
	}

	mask2, err := Casefold(fmt.Sprintf("%s!%s@%s", client.nick, client.username, utils.IPString(client.socket.conn.RemoteAddr())))
	if err == nil && mask2 != mask {
		masks = append(masks, mask2)
	}

	return masks
}

// SetNickname sets the very first nickname for the client.
func (client *Client) SetNickname(nickname string) error {
	if client.HasNick() {
		client.server.logger.Error("nick", fmt.Sprintf("%s nickname already set, something is wrong with server consistency", client.nickMaskString))
		return ErrNickAlreadySet
	}

	err := client.server.clients.Add(client, nickname)
	if err == nil {
		client.updateNick(nickname)
	}
	return err
}

// ChangeNickname changes the existing nickname of the client.
func (client *Client) ChangeNickname(nickname string) error {
	origNickMask := client.nickMaskString
	err := client.server.clients.Replace(client.nick, nickname, client)
	if err == nil {
		client.server.logger.Debug("nick", fmt.Sprintf("%s changed nickname to %s", client.nick, nickname))
		client.server.snomasks.Send(sno.LocalNicks, fmt.Sprintf(ircfmt.Unescape("$%s$r changed nickname to %s"), client.nick, nickname))
		client.server.whoWas.Append(client)
		client.updateNickMask(nickname)
		for friend := range client.Friends() {
			friend.Send(nil, origNickMask, "NICK", nickname)
		}
	}
	return err
}

// LoggedIntoAccount returns true if this client is logged into an account.
func (client *Client) LoggedIntoAccount() bool {
	return client.account != nil && client.account != &NoAccount
}

// RplISupport outputs our ISUPPORT lines to the client. This is used on connection and in VERSION responses.
func (client *Client) RplISupport() {
	for _, tokenline := range client.server.getISupport().CachedReply {
		// ugly trickery ahead
		client.Send(nil, client.server.name, RPL_ISUPPORT, append([]string{client.nick}, tokenline...)...)
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
func (client *Client) destroy() {
	// allow destroy() to execute at most once
	client.stateMutex.Lock()
	isDestroyed := client.isDestroyed
	client.isDestroyed = true
	client.stateMutex.Unlock()
	if isDestroyed {
		return
	}

	client.server.logger.Debug("quit", fmt.Sprintf("%s is no longer on the server", client.nick))

	// send quit/error message to client if they haven't been sent already
	client.Quit("Connection closed")

	client.server.whoWas.Append(client)
	friends := client.Friends()
	friends.Remove(client)

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
	client.server.channelJoinPartMutex.Lock()
	for channel := range client.channels {
		channel.Quit(client)
		for _, member := range channel.Members() {
			friends.Add(member)
		}
	}
	client.server.channelJoinPartMutex.Unlock()

	// clean up server
	client.server.clients.Remove(client)

	// clean up self
	if client.idletimer != nil {
		client.idletimer.Stop()
	}

	client.socket.Close()

	// send quit messages to friends
	for friend := range friends {
		if client.quitMessage == "" {
			client.quitMessage = "Exited"
		}
		friend.Send(nil, client.nickMaskString, "QUIT", client.quitMessage)
	}
	if !client.exitedSnomaskSent {
		client.server.snomasks.Send(sno.LocalQuits, fmt.Sprintf(ircfmt.Unescape("%s$r exited the network"), client.nick))
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
	// attach account-tag
	if client.capabilities.Has(caps.AccountTag) && from.account != &NoAccount {
		if tags == nil {
			tags = ircmsg.MakeTags("account", from.account.Name)
		} else {
			(*tags)["account"] = ircmsg.MakeTagValue(from.account.Name)
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

	return client.Send(tags, from.nickMaskString, command, params...)
}

var (
	// these are all the output commands that MUST have their last param be a trailing.
	// this is needed because silly clients like to treat trailing as separate from the
	// other params in messages.
	commandsThatMustUseTrailing = map[string]bool{
		"PRIVMSG": true,
		"NOTICE":  true,

		RPL_WHOISCHANNELS: true,
		RPL_USERHOST:      true,
	}
)

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

	// force trailing, if message requires it
	var usedTrailingHack bool
	if commandsThatMustUseTrailing[strings.ToUpper(command)] && len(params) > 0 {
		lastParam := params[len(params)-1]
		// to force trailing, we ensure the final param contains a space
		if !strings.Contains(lastParam, " ") {
			params[len(params)-1] = lastParam + " "
			usedTrailingHack = true
		}
	}

	// send out the message
	message := ircmsg.MakeMessage(tags, prefix, command, params...)
	maxlenTags, maxlenRest := client.maxlens()
	line, err := message.LineMaxLen(maxlenTags, maxlenRest)
	if err != nil {
		// try not to fail quietly - especially useful when running tests, as a note to dig deeper
		// log.Println("Error assembling message:")
		// spew.Dump(message)
		// debug.PrintStack()

		message = ircmsg.MakeMessage(nil, client.server.name, ERR_UNKNOWNERROR, "*", "Error assembling message for sending")
		line, _ := message.Line()
		client.socket.Write(line)
		return err
	}

	// is we used the trailing hack, we need to strip the final space we appended earlier
	if usedTrailingHack {
		line = line[:len(line)-3] + "\r\n"
	}

	client.server.logger.Debug("useroutput", client.nick, " ->", strings.TrimRight(line, "\r\n"))

	client.socket.Write(line)
	return nil
}

// Notice sends the client a notice from the server.
func (client *Client) Notice(text string) {
	limit := 400
	if client.capabilities.Has(caps.MaxLine) {
		limit = client.server.getLimits().LineLen.Rest - 110
	}
	lines := wordWrap(text, limit)

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
