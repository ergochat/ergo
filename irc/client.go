// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/DanielOaks/girc-go/ircmsg"
	"github.com/DanielOaks/go-ident"
)

const (
	IDLE_TIMEOUT        = time.Minute + time.Second*30 // how long before a client is considered idle
	QUIT_TIMEOUT        = time.Minute                  // how long after idle before a client is kicked
	IdentTimeoutSeconds = 5
)

var (
	TIMEOUT_STATED_SECONDS = strconv.Itoa(int((IDLE_TIMEOUT + QUIT_TIMEOUT).Seconds()))
	ErrNickAlreadySet      = errors.New("Nickname is already set")
)

// Client is an IRC client.
type Client struct {
	account            *ClientAccount
	atime              time.Time
	authorized         bool
	awayMessage        string
	capabilities       CapabilitySet
	capState           CapState
	capVersion         CapVersion
	certfp             string
	channels           ChannelSet
	class              *OperClass
	ctime              time.Time
	flags              map[UserMode]bool
	isDestroyed        bool
	isQuitting         bool
	hasQuit            bool
	hops               int
	hostname           string
	rawHostname        string
	vhost              string
	idleTimer          *time.Timer
	monitoring         map[string]bool
	nick               string
	nickCasefolded     string
	nickMaskString     string // cache for nickmask string since it's used with lots of replies
	nickMaskCasefolded string
	operName           string
	quitTimer          *time.Timer
	quitMessageSent    bool
	realname           string
	registered         bool
	saslInProgress     bool
	saslMechanism      string
	saslValue          string
	server             *Server
	socket             *Socket
	username           string
	whoisLine          string
}

// NewClient returns a client with all the appropriate info setup.
func NewClient(server *Server, conn net.Conn, isTLS bool) *Client {
	now := time.Now()
	socket := NewSocket(conn)
	client := &Client{
		atime:          now,
		authorized:     server.password == nil,
		capabilities:   make(CapabilitySet),
		capState:       CapNone,
		capVersion:     Cap301,
		channels:       make(ChannelSet),
		ctime:          now,
		flags:          make(map[UserMode]bool),
		monitoring:     make(map[string]bool),
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
	client.Touch()
	go client.run()

	return client
}

//
// command goroutine
//

func (client *Client) maxlens() (int, int) {
	maxlenTags := 512
	maxlenRest := 512
	if client.capabilities[MessageTags] {
		maxlenTags = 4096
	}
	if client.capabilities[MaxLine] {
		if client.server.limits.LineLen.Tags > maxlenTags {
			maxlenTags = client.server.limits.LineLen.Tags
		}
		maxlenRest = client.server.limits.LineLen.Rest
	}
	return maxlenTags, maxlenRest
}

func (client *Client) run() {
	var err error
	var isExiting bool
	var line string
	var msg ircmsg.IrcMessage

	// Set the hostname for this client
	client.rawHostname = AddrLookupHostname(client.socket.conn.RemoteAddr())

	//TODO(dan): Make this a socketreactor from ircbnc
	for {
		line, err = client.socket.Read()
		if err != nil {
			client.Quit("connection closed")
			break
		}

		maxlenTags, maxlenRest := client.maxlens()

		msg, err = ircmsg.ParseLineMaxLen(line, maxlenTags, maxlenRest)
		if err != nil {
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

	// ensure client connection gets closed
	client.destroy()
}

//
// quit timer goroutine
//

func (client *Client) connectionTimeout() {
	client.Quit(fmt.Sprintf("Ping timeout: %s seconds", TIMEOUT_STATED_SECONDS))
	client.isQuitting = true
}

//
// idle timer goroutine
//

func (client *Client) connectionIdle() {
	client.server.idle <- client
}

//
// server goroutine
//

// Active marks the client as 'active' (i.e. the user should be there).
func (client *Client) Active() {
	client.atime = time.Now()
}

// Touch marks the client as alive.
func (client *Client) Touch() {
	if client.quitTimer != nil {
		client.quitTimer.Stop()
	}

	if client.idleTimer == nil {
		client.idleTimer = time.AfterFunc(IDLE_TIMEOUT, client.connectionIdle)
	} else {
		client.idleTimer.Reset(IDLE_TIMEOUT)
	}
}

// Idle resets the timeout handlers and sends the client a PING.
func (client *Client) Idle() {
	client.Send(nil, "", "PING", client.nick)

	if client.quitTimer == nil {
		client.quitTimer = time.AfterFunc(QUIT_TIMEOUT, client.connectionTimeout)
	} else {
		client.quitTimer.Reset(QUIT_TIMEOUT)
	}
}

// Register sets the client details as appropriate when entering the network.
func (client *Client) Register() {
	if client.registered {
		return
	}
	client.registered = true
	client.Touch()

	client.updateNickMask()
	client.alertMonitors()
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

// HasNick returns true if the client's username is set (used in registration).
func (client *Client) HasUsername() bool {
	return client.username != "" && client.username != "*"
}

// HasCapabs returns true if client has the given (role) capabilities.
func (client *Client) HasCapabs(capabs ...string) bool {
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

// <mode>
func (c *Client) ModeString() (str string) {
	str = "+"

	for flag := range c.flags {
		str += flag.String()
	}

	return
}

// Friends refers to clients that share a channel with this client.
func (client *Client) Friends(Capabilities ...Capability) ClientSet {
	friends := make(ClientSet)

	// make sure that I have the right caps
	hasCaps := true
	for _, Cap := range Capabilities {
		if !client.capabilities[Cap] {
			hasCaps = false
			break
		}
	}
	if hasCaps {
		friends.Add(client)
	}

	for channel := range client.channels {
		channel.membersMutex.RLock()
		defer channel.membersMutex.RUnlock()
		for member := range channel.members {
			// make sure they have all the required caps
			for _, Cap := range Capabilities {
				if !member.capabilities[Cap] {
					continue
				}
			}
			friends.Add(member)
		}
	}
	return friends
}

// updateNick updates the casefolded nickname.
func (client *Client) updateNick() {
	casefoldedName, err := CasefoldName(client.nick)
	if err != nil {
		log.Println(fmt.Sprintf("ERROR: Nick [%s] couldn't be casefolded... this should never happen. Printing stacktrace.", client.nick))
		debug.PrintStack()
	}
	client.nickCasefolded = casefoldedName
}

// updateNickMask updates the casefolded nickname and nickmask.
func (client *Client) updateNickMask() {
	client.updateNick()

	if len(client.vhost) > 0 {
		client.hostname = client.vhost
	} else {
		client.hostname = client.rawHostname
	}

	client.nickMaskString = fmt.Sprintf("%s!%s@%s", client.nick, client.username, client.hostname)

	nickMaskCasefolded, err := Casefold(client.nickMaskString)
	if err != nil {
		log.Println(fmt.Sprintf("ERROR: Nickmask [%s] couldn't be casefolded... this should never happen. Printing stacktrace.", client.nickMaskString))
		debug.PrintStack()
	}
	client.nickMaskCasefolded = nickMaskCasefolded
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

	mask2, err := Casefold(fmt.Sprintf("%s!%s@%s", client.nick, client.username, IPString(client.socket.conn.RemoteAddr())))
	if err == nil && mask2 != mask {
		masks = append(masks, mask2)
	}

	return masks
}

// SetNickname sets the very first nickname for the client.
func (client *Client) SetNickname(nickname string) error {
	if client.HasNick() {
		Log.error.Printf("%s nickname already set!", client.nickMaskString)
		return ErrNickAlreadySet
	}

	err := client.server.clients.Add(client, nickname)
	if err == nil {
		client.nick = nickname
		client.updateNick()
	}
	return err
}

// ChangeNickname changes the existing nickname of the client.
func (client *Client) ChangeNickname(nickname string) error {
	origNickMask := client.nickMaskString
	err := client.server.clients.Replace(client.nick, nickname, client)
	if err == nil {
		client.server.whoWas.Append(client)
		client.nick = nickname
		client.updateNickMask()
		for friend := range client.Friends() {
			friend.Send(nil, origNickMask, "NICK", nickname)
		}
	}
	return err
}

func (client *Client) Quit(message string) {
	if !client.quitMessageSent {
		client.Send(nil, client.nickMaskString, "QUIT", message)
		client.Send(nil, client.nickMaskString, "ERROR", message)
		client.quitMessageSent = true
	}
}

// destroy gets rid of a client, removes them from server lists etc.
func (client *Client) destroy() {
	if client.isDestroyed {
		return
	}

	// send quit/error message to client if they haven't been sent already
	client.Quit("Connection closed")

	client.isDestroyed = true
	client.server.whoWas.Append(client)
	friends := client.Friends()
	friends.Remove(client)

	// remove from connection limits
	ipaddr := net.ParseIP(IPString(client.socket.conn.RemoteAddr()))
	// this check shouldn't be required but eh
	if ipaddr != nil {
		client.server.connectionLimitsMutex.Lock()
		client.server.connectionLimits.RemoveClient(ipaddr)
		client.server.connectionLimitsMutex.Unlock()
	}

	// remove from opers list
	_, exists := client.server.currentOpers[client]
	if exists {
		delete(client.server.currentOpers, client)
	}

	// alert monitors
	for _, mClient := range client.server.monitoring[client.nickCasefolded] {
		mClient.Send(nil, client.server.name, RPL_MONOFFLINE, mClient.nick, client.nick)
	}

	// remove my monitors
	client.clearMonitorList()

	// clean up channels
	for channel := range client.channels {
		channel.Quit(client)
	}

	// clean up server
	client.server.clients.Remove(client)

	// clean up self
	if client.idleTimer != nil {
		client.idleTimer.Stop()
	}
	if client.quitTimer != nil {
		client.quitTimer.Stop()
	}

	client.socket.Close()

	// send quit messages to friends
	for friend := range friends {
		//TODO(dan): store quit message in user, if exists use that instead here
		friend.Send(nil, client.nickMaskString, "QUIT", "Exited")
	}
}

// SendSplitMsgFromClient sends an IRC PRIVMSG/NOTICE coming from a specific client.
// Adds account-tag to the line as well.
func (client *Client) SendSplitMsgFromClient(msgid string, from *Client, tags *map[string]ircmsg.TagValue, command, target string, message SplitMessage) {
	if client.capabilities[MaxLine] {
		client.SendFromClient(msgid, from, tags, from.nickMaskString, command, target, message.ForMaxLine)
	} else {
		for _, str := range message.For512 {
			client.SendFromClient(msgid, from, tags, from.nickMaskString, command, target, str)
		}
	}
}

// SendFromClient sends an IRC line coming from a specific client.
// Adds account-tag to the line as well.
func (client *Client) SendFromClient(msgid string, from *Client, tags *map[string]ircmsg.TagValue, command string, params ...string) error {
	// attach account-tag
	if client.capabilities[AccountTag] && from.account != &NoAccount {
		if tags == nil {
			tags = ircmsg.MakeTags("account", from.account.Name)
		} else {
			(*tags)["account"] = ircmsg.MakeTagValue(from.account.Name)
		}
	}
	// attach message-id
	if len(msgid) > 0 && client.capabilities[MessageIDs] {
		if tags == nil {
			tags = ircmsg.MakeTags("draft/msgid", msgid)
		} else {
			(*tags)["draft/msgid"] = ircmsg.MakeTagValue(msgid)
		}
	}

	return client.Send(tags, from.nickMaskString, command, params...)
}

// Send sends an IRC line to the client.
func (client *Client) Send(tags *map[string]ircmsg.TagValue, prefix string, command string, params ...string) error {
	// attach server-time
	if client.capabilities[ServerTime] {
		if tags == nil {
			tags = ircmsg.MakeTags("time", time.Now().Format("2006-01-02T15:04:05.999Z"))
		} else {
			(*tags)["time"] = ircmsg.MakeTagValue(time.Now().Format("2006-01-02T15:04:05.999Z"))
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
	client.socket.Write(line)
	return nil
}

// Notice sends the client a notice from the server.
func (client *Client) Notice(text string) {
	client.Send(nil, client.server.name, "NOTICE", client.nick, text)
}
