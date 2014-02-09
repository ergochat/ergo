package irc

import (
	"fmt"
	"log"
	"net"
	"time"
)

type Client struct {
	atime      time.Time
	away       bool
	channels   ChannelSet
	conn       net.Conn
	hostname   string
	invisible  bool
	nick       string
	realname   string
	registered bool
	replies    chan<- Reply
	server     *Server
	serverPass bool
	username   string
}

type ClientSet map[*Client]bool

func NewClient(server *Server, conn net.Conn) *Client {
	read := StringReadChan(conn)
	write := StringWriteChan(conn)
	replies := make(chan Reply)

	client := &Client{
		channels:   make(ChannelSet),
		conn:       conn,
		hostname:   LookupHostname(conn.RemoteAddr()),
		replies:    replies,
		server:     server,
		serverPass: server.password == "",
	}

	go client.readConn(read)
	go client.writeConn(write, replies)

	return client
}

func (c *Client) readConn(recv <-chan string) {
	for str := range recv {
		m, err := ParseCommand(str)
		if err != nil {
			if err == NotEnoughArgsError {
				c.replies <- ErrNeedMoreParams(c.server, str)
			} else {
				c.replies <- ErrUnknownCommand(c.server, str)
			}
			continue
		}

		m.SetBase(c)
		c.server.commands <- m
	}
}

func (c *Client) writeConn(write chan<- string, replies <-chan Reply) {
	for reply := range replies {
		if DEBUG_CLIENT {
			log.Printf("%s ← %s : %s", c, reply.Source(), reply)
		}
		reply.Format(c, write)
	}
}

func (client *Client) Destroy() *Client {
	client.conn.Close()
	return client
}

func (c *Client) Replies() chan<- Reply {
	return c.replies
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
			clients[member] = true
		}
	}
	return clients
}

func (c *Client) UModeString() string {
	if c.invisible {
		return "i"
	}
	return ""
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
