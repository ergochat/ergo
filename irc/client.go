package irc

import (
	"fmt"
	"net"
	"time"
)

const (
	IDLE_TIMEOUT = time.Minute // how long before a client is considered idle
	QUIT_TIMEOUT = time.Minute // how long after idle before a client is kicked
)

type Client struct {
	atime        time.Time
	authorized   bool
	awayMessage  Text
	capabilities CapabilitySet
	capState     CapState
	channels     ChannelSet
	ctime        time.Time
	flags        map[UserMode]bool
	hasQuit      bool
	hops         uint
	hostname     Name
	idleTimer    *time.Timer
	nick         Name
	quitTimer    *time.Timer
	realname     Text
	registered   bool
	server       *Server
	socket       *Socket
	username     Name
}

func NewClient(server *Server, conn net.Conn) *Client {
	now := time.Now()
	client := &Client{
		atime:        now,
		authorized:   server.password == nil,
		capState:     CapNone,
		capabilities: make(CapabilitySet),
		channels:     make(ChannelSet),
		ctime:        now,
		flags:        make(map[UserMode]bool),
		server:       server,
		socket:       NewSocket(conn),
	}
	client.Touch()
	go client.run()

	return client
}

//
// command goroutine
//

func (client *Client) run() {
	var command Command
	var err error
	var line string

	// Set the hostname for this client. The client may later send a PROXY
	// command from stunnel that sets the hostname to something more accurate.
	client.hostname = AddrLookupHostname(client.socket.conn.RemoteAddr())

	for err == nil {
		//TODO(dan): does this read sockets correctly and split lines properly? (think that ZNC bug that kept happening with mammon)
		if line, err = client.socket.Read(); err != nil {
			command = NewQuitCommand("connection closed")

		} else if command, err = ParseCommand(line); err != nil {
			switch err {
			case ErrParseCommand:
				//TODO(dan): why is this a notice? there's a proper numeric for this I swear
				client.Reply(RplNotice(client.server, client,
					NewText("failed to parse command")))
			}
			// so the read loop will continue
			err = nil
			continue

		} else if checkPass, ok := command.(checkPasswordCommand); ok {
			checkPass.LoadPassword(client.server)
			// Block the client thread while handling a potentially expensive
			// password bcrypt operation. Since the server is single-threaded
			// for commands, we don't want the server to perform the bcrypt,
			// blocking anyone else from sending commands until it
			// completes. This could be a form of DoS if handled naively.
			checkPass.CheckPassword()
		}

		client.send(command)
	}
}

func (client *Client) send(command Command) {
	command.SetClient(client)
	client.server.commands <- command
}

// quit timer goroutine

func (client *Client) connectionTimeout() {
	client.send(NewQuitCommand("connection timeout"))
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
	client.Reply(RplPing(client.server))

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

func (client *Client) destroy() {
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

	Log.debug.Printf("%s: destroyed", client)
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

func (client *Client) SetNickname(nickname Name) {
	if client.HasNick() {
		Log.error.Printf("%s nickname already set!", client)
		return
	}
	client.nick = nickname
	client.server.clients.Add(client)
}

func (client *Client) ChangeNickname(nickname Name) {
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

func (client *Client) Reply(reply string) error {
	return client.socket.Write(reply)
}

func (client *Client) Quit(message Text) {
	if client.hasQuit {
		return
	}

	client.hasQuit = true
	client.Reply(RplError("quit"))
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
