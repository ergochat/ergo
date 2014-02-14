package irc

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

type Client struct {
	atime       time.Time
	away        bool
	awayMessage string
	channels    ChannelSet
	conn        net.Conn
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
	authorized  bool
	username    string
}

func NewClient(server *Server, conn net.Conn) *Client {
	client := &Client{
		channels: make(ChannelSet),
		conn:     conn,
		hostname: AddrLookupHostname(conn.RemoteAddr()),
		replies:  make(chan Reply),
		server:   server,
	}
	client.loginTimer = time.AfterFunc(LOGIN_TIMEOUT, client.Destroy)

	go client.readConn()
	go client.writeConn()

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
	client.server.commands <- msg
}

func (client *Client) ConnectionClosed() {
	msg := &QuitCommand{
		message: "connection closed",
	}
	msg.SetClient(client)
	client.server.commands <- msg
}

func (c *Client) readConn() {
	recv := bufio.NewReader(c.conn)

	for {
		line, err := recv.ReadString('\n')
		if err != nil {
			if DEBUG_NET {
				log.Printf("%s → error: %s", c.conn.RemoteAddr(), err)
			}
			break
		}

		line = strings.TrimSpace(line)
		if DEBUG_NET {
			log.Printf("%s → %s", c.conn.RemoteAddr(), line)
		}

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
		c.server.commands <- m
	}
	c.ConnectionClosed()
}

func (client *Client) maybeLogWriteError(err error) bool {
	if err != nil {
		if DEBUG_NET {
			log.Printf("%s ← error: %s", client.conn.RemoteAddr(), err)
		}
		return true
	}
	return false
}

func (client *Client) writeConn() {
	send := bufio.NewWriter(client.conn)

	for reply := range client.replies {
		if DEBUG_CLIENT {
			log.Printf("%s ← %s %s", client, reply.Source(), reply)
		}
		for _, str := range reply.Format(client) {
			if DEBUG_NET {
				log.Printf("%s ← %s", client.conn.RemoteAddr(), str)
			}
			if _, err := send.WriteString(str); client.maybeLogWriteError(err) {
				break
			}
			if _, err := send.WriteString(CRLF); client.maybeLogWriteError(err) {
				break
			}
			if err := send.Flush(); client.maybeLogWriteError(err) {
				break
			}
		}
	}
	client.ConnectionClosed()
}

func (client *Client) Destroy() {
	if client.destroyed {
		return
	}

	client.conn.Close()

	close(client.replies)
	client.replies = nil

	if client.idleTimer != nil {
		client.idleTimer.Stop()
	}

	if client.quitTimer != nil {
		client.quitTimer.Stop()
	}

	// clear channel list
	client.channels = make(ChannelSet)

	client.server.clients.Remove(client)

	client.destroyed = true
}

func (client *Client) Reply(replies ...Reply) {
	if client.replies == nil {
		return
	}
	for _, reply := range replies {
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
