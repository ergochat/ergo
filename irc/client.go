package irc

import (
	"fmt"
	"log"
	"net"
	"time"
)

func IsNickname(nick string) bool {
	return NicknameExpr.MatchString(nick)
}

type Client struct {
	atime        time.Time
	authorized   bool
	awayMessage  string
	capabilities CapabilitySet
	capState     CapState
	channels     ChannelSet
	commands     chan Command
	ctime        time.Time
	flags        map[UserMode]bool
	hasQuit      bool
	hops         uint
	hostname     string
	idleTimer    *time.Timer
	loginTimer   *time.Timer
	nick         string
	phase        Phase
	quitTimer    *time.Timer
	realname     string
	server       *Server
	socket       *Socket
	username     string
}

func NewClient(server *Server, conn net.Conn) *Client {
	now := time.Now()
	client := &Client{
		atime:        now,
		authorized:   server.password == nil,
		capState:     CapNone,
		capabilities: make(CapabilitySet),
		channels:     make(ChannelSet),
		commands:     make(chan Command),
		ctime:        now,
		flags:        make(map[UserMode]bool),
		phase:        Registration,
		server:       server,
	}
	client.socket = NewSocket(conn, client.commands)
	client.loginTimer = time.AfterFunc(LOGIN_TIMEOUT, client.connectionTimeout)
	go client.run()

	return client
}

//
// command goroutine
//

func (client *Client) run() {
	for command := range client.commands {
		command.SetClient(client)

		checkPass, ok := command.(checkPasswordCommand)
		if ok {
			checkPass.LoadPassword(client.server)
			checkPass.CheckPassword()
		}

		client.server.commands <- command
	}
}

func (client *Client) connectionTimeout() {
	client.commands <- &QuitCommand{
		message: "connection timeout",
	}
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
	client.Reply(RplPing(client))

	if client.quitTimer == nil {
		client.quitTimer = time.AfterFunc(QUIT_TIMEOUT, client.connectionTimeout)
	} else {
		client.quitTimer.Reset(QUIT_TIMEOUT)
	}
}

func (client *Client) Register() {
	client.phase = Normal
	client.loginTimer.Stop()
	client.Touch()
}

func (client *Client) destroy() {
	// clean up channels

	for channel := range client.channels {
		channel.Quit(client)
	}

	// clean up server

	client.server.clients.Remove(client)

	// clean up self

	if client.loginTimer != nil {
		client.loginTimer.Stop()
	}
	if client.idleTimer != nil {
		client.idleTimer.Stop()
	}
	if client.quitTimer != nil {
		client.quitTimer.Stop()
	}

	client.socket.Close()

	if DEBUG_CLIENT {
		log.Printf("%s: destroyed", client)
	}
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

func (c *Client) UserHost() string {
	username := "*"
	if c.HasUsername() {
		username = c.username
	}
	return fmt.Sprintf("%s!%s@%s", c.Nick(), username, c.hostname)
}

func (c *Client) Nick() string {
	if c.HasNick() {
		return c.nick
	}
	return "*"
}

func (c *Client) Id() string {
	return c.UserHost()
}

func (c *Client) String() string {
	return c.Id()
}

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

func (client *Client) SetNickname(nickname string) {
	client.nick = nickname
	client.server.clients.Add(client)
}

func (client *Client) ChangeNickname(nickname string) {
	// Make reply before changing nick to capture original source id.
	reply := RplNick(client, nickname)
	client.server.clients.Remove(client)
	client.server.whoWas.Append(client)
	client.nick = nickname
	client.server.clients.Add(client)
	for friend := range client.Friends() {
		friend.Reply(reply)
	}
}

func (client *Client) Reply(reply string, args ...interface{}) {
	if len(args) > 0 {
		reply = fmt.Sprintf(reply, args...)
	}
	client.socket.Write(reply)
}

func (client *Client) Quit(message string) {
	if client.hasQuit {
		return
	}

	client.Reply(RplError("connection closed"))
	client.hasQuit = true
	client.server.whoWas.Append(client)
	friends := client.Friends()
	friends.Remove(client)
	client.destroy()

	if len(friends) > 0 {
		reply := RplQuit(client, message)
		for friend := range friends {
			friend.Reply(reply)
		}
	}
}
