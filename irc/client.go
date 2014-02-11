package irc

import (
	"fmt"
	"log"
	"net"
	"time"
)

type Client struct {
	away       bool
	channels   ChannelSet
	conn       net.Conn
	hostname   string
	invisible  bool
	nick       string
	operator   bool
	realname   string
	registered bool
	replies    chan<- Reply
	server     *Server
	serverPass bool
	username   string
	idleTimer  *time.Timer
	quitTimer  *time.Timer
}

func NewClient(server *Server, conn net.Conn) *Client {
	read := StringReadChan(conn)
	write := StringWriteChan(conn)
	replies := make(chan Reply)

	client := &Client{
		channels: make(ChannelSet),
		conn:     conn,
		hostname: AddrLookupHostname(conn.RemoteAddr()),
		replies:  replies,
		server:   server,
	}

	go client.readConn(read)
	go client.writeConn(write, replies)

	client.Touch()
	return client
}

func (client *Client) Touch() {
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
		client.quitTimer = time.AfterFunc(QUIT_TIMEOUT, client.Quit)
	} else {
		client.quitTimer.Reset(QUIT_TIMEOUT)
	}
	client.Reply(RplPing(client.server, client))
}

func (client *Client) Quit() {
	msg := &QuitCommand{
		message: "connection timeout",
	}
	msg.SetClient(client)
	client.server.commands <- msg
}

func (c *Client) readConn(recv <-chan string) {
	for str := range recv {
		m, err := ParseCommand(str)
		if err != nil {
			if err == NotEnoughArgsError {
				c.Reply(ErrNeedMoreParams(c.server, str))
			} else {
				c.Reply(ErrUnknownCommand(c.server, str))
			}
			continue
		}

		m.SetClient(c)
		c.server.commands <- m
	}
}

func (c *Client) writeConn(write chan<- string, replies <-chan Reply) {
	for reply := range replies {
		if DEBUG_CLIENT {
			log.Printf("%s ← %s %s", c, reply.Source(), reply)
		}
		reply.Format(c, write)
	}
}

func (client *Client) Destroy() error {
	if client.replies == nil {
		return ErrAlreadyDestroyed
	}

	close(client.replies)
	client.replies = nil
	client.conn.Close()
	if client.idleTimer != nil {
		client.idleTimer.Stop()
	}
	if client.quitTimer != nil {
		client.quitTimer.Stop()
	}
	return nil
}

func (client *Client) Reply(reply Reply) error {
	if client.replies == nil {
		return ErrAlreadyDestroyed
	}
	client.replies <- reply
	return nil
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
	nick := c.nick
	if nick == "" {
		nick = "*"
	}
	username := c.username
	if username == "" {
		username = "*"
	}
	return fmt.Sprintf("%s!%s@%s", nick, username, c.hostname)
}

func (c *Client) Nick() string {
	return c.nick
}

func (c *Client) Id() string {
	return c.UserHost()
}

func (c *Client) String() string {
	return c.UserHost()
}
