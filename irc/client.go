// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"log"
	"net"
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
	atime          time.Time
	authorized     bool
	awayMessage    string
	capabilities   CapabilitySet
	capState       CapState
	channels       ChannelSet
	ctime          time.Time
	flags          map[UserMode]bool
	isQuitting     bool
	hasQuit        bool
	hops           uint
	hostname       Name
	idleTimer      *time.Timer
	nick           Name
	nickString     string // cache for nick string since it's used with most numerics
	nickMaskString string // cache for nickmask string since it's used with lots of replies
	quitTimer      *time.Timer
	realname       string
	registered     bool
	server         *Server
	socket         *Socket
	username       Name
	isDestroyed    bool
}

func NewClient(server *Server, conn net.Conn, isTLS bool) *Client {
	now := time.Now()
	socket := NewSocket(conn)
	client := &Client{
		atime:        now,
		authorized:   server.password == nil,
		capState:     CapNone,
		capabilities: make(CapabilitySet),
		channels:     make(ChannelSet),
		ctime:        now,
		flags:        make(map[UserMode]bool),
		server:       server,
		socket:       &socket,
		nickString:   "*", // * is used until actual nick is given
	}
	if isTLS {
		client.flags[TLS] = true
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
			//TODO(dan): replace this with IsUsername/IsIRCName?
			if Name(username).IsNickname() {
				client.Notice("*** Found your username")
				client.username = Name(username)
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

	// Set the hostname for this client. The client may later send a PROXY
	// command from stunnel that sets the hostname to something more accurate.
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
			client.Send(nil, client.server.nameString, ERR_UNKNOWNCOMMAND, client.nickString, msg.Command, "Unknown command")
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
	client.Send(nil, "", "PING", client.nickString)

	if client.quitTimer == nil {
		client.quitTimer = time.AfterFunc(QUIT_TIMEOUT, client.connectionTimeout)
	} else {
		client.quitTimer.Reset(QUIT_TIMEOUT)
	}
}

func (client *Client) Register() {
	if client.registered {
		return
	}
	client.registered = true
	client.Touch()
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
	return client.nick != ""
}

func (client *Client) HasUsername() bool {
	return client.username != ""
}

// <mode>
func (c *Client) ModeString() (str string) {
	for flag := range c.flags {
		str += flag.String()
	}

	if len(str) > 0 {
		str = "+" + str
	}
	return
}

func (c *Client) UserHost() Name {
	username := "*"
	if c.HasUsername() {
		username = c.username.String()
	}
	return Name(fmt.Sprintf("%s!%s@%s", c.Nick(), username, c.hostname))
}

func (c *Client) Nick() Name {
	if c.HasNick() {
		return c.nick
	}
	return Name("*")
}

func (c *Client) Id() Name {
	return c.UserHost()
}

func (c *Client) String() string {
	return c.Id().String()
}

// Friends refers to clients that share a channel with this client.
func (client *Client) Friends() ClientSet {
	friends := make(ClientSet)
	friends.Add(client)
	for channel := range client.channels {
		for member := range channel.members {
			friends.Add(member)
		}
	}
	return friends
}

func (client *Client) updateNickMask() {
	client.nickString = client.nick.String()
	client.nickMaskString = fmt.Sprintf("%s!%s@%s", client.nickString, client.username, client.hostname)
}

func (client *Client) SetNickname(nickname Name) {
	if client.HasNick() {
		Log.error.Printf("%s nickname already set!", client)
		return
	}
	client.nick = nickname
	client.updateNickMask()
	client.server.clients.Add(client)
}

func (client *Client) ChangeNickname(nickname Name) {
	origNickMask := client.nickMaskString
	client.server.clients.Remove(client)
	client.server.whoWas.Append(client)
	client.nick = nickname
	client.updateNickMask()
	client.server.clients.Add(client)
	client.Send(nil, origNickMask, "NICK", nickname.String())
	for friend := range client.Friends() {
		friend.Send(nil, origNickMask, "NICK", nickname.String())
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

// Send sends an IRC line to the client.
func (client *Client) Send(tags *map[string]ircmsg.TagValue, prefix string, command string, params ...string) error {
	// attach server-time
	if client.capabilities[ServerTime] {
		if tags == nil {
			tags = ircmsg.MakeTags("time", time.Now().Format(time.RFC3339))
		} else {
			(*tags)["time"] = ircmsg.MakeTagValue(time.Now().Format(time.RFC3339))
		}
	}

	// send out the message
	ircmsg := ircmsg.MakeMessage(tags, prefix, command, params...)
	line, err := ircmsg.Line()
	if err != nil {
		return err
	}
	client.socket.Write(line)
	return nil
}

// Notice sends the client a notice from the server.
func (client *Client) Notice(text string) {
	client.Send(nil, client.server.nameString, "NOTICE", client.nickString, text)
}
