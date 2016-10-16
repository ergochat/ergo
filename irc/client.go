// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
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
	IdentTimeoutSeconds = 8
)

var (
	TIMEOUT_STATED_SECONDS = strconv.Itoa(int((IDLE_TIMEOUT + QUIT_TIMEOUT).Seconds()))
)

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
	ctime              time.Time
	flags              map[UserMode]bool
	isDestroyed        bool
	isQuitting         bool
	hasQuit            bool
	hops               int
	hostname           string
	idleTimer          *time.Timer
	monitoring         map[string]bool
	nick               string
	nickCasefolded     string
	nickMaskString     string // cache for nickmask string since it's used with lots of replies
	nickMaskCasefolded string
	quitTimer          *time.Timer
	realname           string
	registered         bool
	saslInProgress     bool
	saslMechanism      string
	saslValue          string
	server             *Server
	socket             *Socket
	username           string
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

func (client *Client) run() {
	var err error
	var isExiting bool
	var line string
	var msg ircmsg.IrcMessage

	// Set the hostname for this client
	client.hostname = AddrLookupHostname(client.socket.conn.RemoteAddr())

	//TODO(dan): Make this a socketreactor from ircbnc
	for {
		line, err = client.socket.Read()
		if err != nil {
			client.Quit("connection closed")
			break
		}

		msg, err = ircmsg.ParseLine(line)
		if err != nil {
			client.Quit("received malformed line")
			break
		}

		cmd, exists := Commands[msg.Command]
		if !exists {
			client.Send(nil, client.server.name, ERR_UNKNOWNCOMMAND, client.nick, msg.Command, "Unknown command")
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

func (client *Client) Active() {
	client.atime = time.Now()
}

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

func (client *Client) IdleTime() time.Duration {
	return time.Since(client.atime)
}

func (client *Client) SignonTime() int64 {
	return client.ctime.Unix()
}

func (client *Client) IdleSeconds() uint64 {
	return uint64(client.IdleTime().Seconds())
}

func (client *Client) HasNick() bool {
	return client.nick != "" && client.nick != "*"
}

func (client *Client) HasUsername() bool {
	return client.username != "" && client.username != "*"
}

// <mode>
func (c *Client) ModeString() (str string) {
	str = "+"

	for flag := range c.flags {
		str += flag.String()
	}

	return
}

func (c *Client) UserHost() string {
	return fmt.Sprintf("%s!%s@%s", c.nick, c.username, c.hostname)
}

func (c *Client) Id() string {
	return c.UserHost()
}

// Friends refers to clients that share a channel with this client.
func (client *Client) Friends(Capabilities ...Capability) ClientSet {
	friends := make(ClientSet)
	friends.Add(client)
	for channel := range client.channels {
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

	client.nickMaskString = fmt.Sprintf("%s!%s@%s", client.nick, client.username, client.hostname)

	nickMaskCasefolded, err := Casefold(client.nickMaskString)
	if err != nil {
		log.Println(fmt.Sprintf("ERROR: Nickmask [%s] couldn't be casefolded... this should never happen. Printing stacktrace.", client.nickMaskString))
		debug.PrintStack()
	}
	client.nickMaskCasefolded = nickMaskCasefolded
}

func (client *Client) SetNickname(nickname string) {
	if client.HasNick() {
		Log.error.Printf("%s nickname already set!", client.nickMaskString)
		return
	}
	client.nick = nickname
	client.updateNick()
	client.server.clients.Add(client)
}

func (client *Client) ChangeNickname(nickname string) {
	origNickMask := client.nickMaskString
	client.server.clients.Remove(client)
	client.server.whoWas.Append(client)
	client.nick = nickname
	client.updateNickMask()
	client.server.clients.Add(client)
	for friend := range client.Friends() {
		friend.Send(nil, origNickMask, "NICK", nickname)
	}
}

func (client *Client) Reply(reply string) error {
	//TODO(dan): We'll be passing around real message objects instead of raw strings
	return client.socket.WriteLine(reply)
}

func (client *Client) Quit(message string) {
	client.Send(nil, client.nickMaskString, "QUIT", message)
	client.Send(nil, client.nickMaskString, "ERROR", message)
}

func (client *Client) destroy() {
	if client.isDestroyed {
		return
	}

	client.isDestroyed = true
	client.server.whoWas.Append(client)
	friends := client.Friends()
	friends.Remove(client)

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
	for friend := range client.Friends() {
		//TODO(dan): store quit message in user, if exists use that instead here
		friend.Send(nil, client.nickMaskString, "QUIT", "Exited")
	}
}

// SendFromClient sends an IRC line coming from a specific client.
// Adds account-tag to the line as well.
func (client *Client) SendFromClient(from *Client, tags *map[string]ircmsg.TagValue, prefix string, command string, params ...string) error {
	// attach account-tag
	if client.capabilities[AccountTag] && from.account != &NoAccount {
		if tags == nil {
			tags = ircmsg.MakeTags("account", from.account.Name)
		} else {
			(*tags)["account"] = ircmsg.MakeTagValue(from.account.Name)
		}
	}

	return client.Send(tags, prefix, command, params...)
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
	line, err := message.Line()
	if err != nil {
		// try not to fail quietly - especially useful when running tests, as a note to dig deeper
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
