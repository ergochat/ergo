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
	ctime       time.Time
	destroyed   bool
	hostname    string
	idleTimer   *time.Timer
	invisible   bool
	loginTimer  *time.Timer
	nick        string
	operator    bool
	quitTimer   *time.Timer
	realname    string
	registered  bool
	replies     chan Reply
	server      *Server
	socket      *Socket
	authorized  bool
	username    string
}

func NewClient(server *Server, conn net.Conn) *Client {
	now := time.Now()
	client := &Client{
		atime:    now,
		channels: make(ChannelSet),
		ctime:    now,
		hostname: AddrLookupHostname(conn.RemoteAddr()),
		replies:  make(chan Reply),
		server:   server,
		socket:   NewSocket(conn),
	}
	client.loginTimer = time.AfterFunc(LOGIN_TIMEOUT, client.Destroy)

	go client.readCommands()
	go client.writeReplies()

	return client
}

func (client *Client) Touch() {
	if client.destroyed {
		return
	}

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
	if client.destroyed {
		return
	}

	msg := &QuitCommand{
		message: "connection closed",
	}
	msg.SetClient(client)
	client.server.Command(msg)
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

	if c.registered {
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
			close(client.replies)
		}
	}
	client.replies = nil
}

func (client *Client) Destroy() {
	if client.destroyed {
		return
	}

	if DEBUG_CLIENT {
		log.Printf("%s destroying", client)
	}

	client.destroyed = true

	if client.replies != nil {
		close(client.replies)
	}

	client.socket.Close()

	if client.idleTimer != nil {
		client.idleTimer.Stop()
	}

	if client.quitTimer != nil {
		client.quitTimer.Stop()
	}

	// clear channel list
	client.channels = make(ChannelSet)

	client.server.clients.Remove(client)

	if DEBUG_CLIENT {
		log.Printf("%s destroyed", client)
	}
}

func (client *Client) Reply(replies ...Reply) {
	for _, reply := range replies {
		if client.replies == nil {
			if DEBUG_CLIENT {
				log.Printf("%s dropped %s", client, reply)
			}
			continue
		}
		client.replies <- reply
	}
}

func (client *Client) HasNick() bool {
	return client.nick != ""
}

func (client *Client) HasUsername() bool {
	return client.username != ""
}

func (client *Client) InterestedClients() ClientSet {
	clients := make(ClientSet)
	for channel := range client.channels {
		for member := range channel.members {
			clients.Add(member)
		}
	}
	return clients
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
