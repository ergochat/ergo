package irc

import (
	"fmt"
	"log"
	"net"
	"time"
)

type Client struct {
	atime       time.Time
	away        bool
	awayMessage string
	channels    ChannelSet
	commands    chan ClientCommand
	ctime       time.Time
	friends     map[*Client]uint
	hostname    string
	idleTimer   *time.Timer
	invisible   bool
	loginTimer  *time.Timer
	nick        string
	operator    bool
	phase       Phase
	quitTimer   *time.Timer
	realname    string
	replies     chan Reply
	server      *Server
	socket      *Socket
	username    string
}

func NewClient(server *Server, conn net.Conn) *Client {
	now := time.Now()
	client := &Client{
		atime:    now,
		channels: make(ChannelSet),
		commands: make(chan ClientCommand),
		ctime:    now,
		friends:  make(map[*Client]uint),
		hostname: AddrLookupHostname(conn.RemoteAddr()),
		phase:    server.InitPhase(),
		replies:  make(chan Reply),
		server:   server,
		socket:   NewSocket(conn),
	}

	client.loginTimer = time.AfterFunc(LOGIN_TIMEOUT, client.Destroy)
	go client.readClientCommands()
	go client.readCommands()
	go client.writeReplies()

	return client
}

func (client *Client) Touch() {
	client.atime = time.Now()

	if client.quitTimer != nil {
		client.quitTimer.Stop()
	}

	if client.idleTimer == nil {
		client.idleTimer = time.AfterFunc(IDLE_TIMEOUT, client.Idle)
	} else {
		client.idleTimer.Reset(IDLE_TIMEOUT)
	}
}

func (client *Client) Idle() {
	if client.quitTimer == nil {
		client.quitTimer = time.AfterFunc(QUIT_TIMEOUT, client.ConnectionTimeout)
	} else {
		client.quitTimer.Reset(QUIT_TIMEOUT)
	}

	client.Reply(RplPing(client.server, client))
}

func (client *Client) ConnectionTimeout() {
	msg := &QuitCommand{
		message: "connection timeout",
	}
	msg.SetClient(client)
	client.server.Command(msg)
}

func (client *Client) ConnectionClosed() {
	msg := &QuitCommand{
		message: "connection closed",
	}
	msg.SetClient(client)
	client.server.Command(msg)
}

func (client *Client) readClientCommands() {
	for command := range client.commands {
		command.HandleClient(client)
	}
}

func (c *Client) readCommands() {
	for line := range c.socket.Read() {
		m, err := ParseCommand(line)
		if err != nil {
			switch err {
			case NotEnoughArgsError:
				c.Reply(ErrNeedMoreParams(c.server, line))
			default:
				c.Reply(ErrUnknownCommand(c.server, line))
			}
			continue
		}

		m.SetClient(c)
		c.server.Command(m)
	}

	if c.phase == Normal {
		c.ConnectionClosed()
	} else {
		c.Destroy()
	}
}

func (client *Client) writeReplies() {
	for reply := range client.replies {
		if DEBUG_CLIENT {
			log.Printf("%s ← %s", client, reply)
		}

		if client.socket.Write(reply.Format(client)) != nil {
			break
		}
	}
}

type DestroyClient struct {
	BaseCommand
	client *Client
}

func (client *Client) Destroy() {
	client.socket.Close()

	if client.idleTimer != nil {
		client.idleTimer.Stop()
	}

	if client.quitTimer != nil {
		client.quitTimer.Stop()
	}

	cmd := &DestroyClient{
		client: client,
	}

	for channel := range client.channels {
		channel.Command(cmd)
	}

	client.server.Command(cmd)
}

func (client *Client) Reply(reply Reply) {
	if client.replies == nil {
		if DEBUG_CLIENT {
			log.Printf("%s dropped %s", client, reply)
		}
		return
	}
	client.replies <- reply
}

func (client *Client) HasNick() bool {
	return client.nick != ""
}

func (client *Client) HasUsername() bool {
	return client.username != ""
}

// <mode>
func (c *Client) ModeString() (str string) {
	if c.invisible {
		str += Invisible.String()
	}
	if c.operator {
		str += Operator.String()
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
	return c.UserHost()
}

//
// commands
//

type AddFriend struct {
	client *Client
}

func (msg *AddFriend) HandleClient(client *Client) {
	client.friends[msg.client] += 1
}

type RemoveFriend struct {
	client *Client
}

func (msg *RemoveFriend) HandleClient(client *Client) {
	client.friends[msg.client] -= 1
	if client.friends[msg.client] <= 0 {
		delete(client.friends, msg.client)
	}
}

func (msg *JoinChannel) HandleClient(client *Client) {
	client.channels.Add(msg.channel)
}

func (msg *PartChannel) HandleClient(client *Client) {
	client.channels.Remove(msg.channel)
}

func (msg *NickCommand) HandleClient(client *Client) {
	// Make reply before changing nick.
	reply := RplNick(client, msg.nickname)

	client.nick = msg.nickname

	for friend := range client.friends {
		friend.Reply(reply)
	}
}

func (msg *QuitCommand) HandleClient(client *Client) {
	if len(client.friends) > 0 {
		reply := RplQuit(client, msg.message)
		for friend := range client.friends {
			if friend == client {
				continue
			}
			friend.Reply(reply)
		}
	}

	for channel := range client.channels {
		channel.commands <- msg
	}

	client.Destroy()
}
