package irc

import (
	"fmt"
	"log"
	"net"
	"time"
)

type Client struct {
	conn       net.Conn
	send       chan<- Reply
	recv       <-chan string
	username   string
	realname   string
	hostname   string
	nick       string
	serverPass bool
	registered bool
	away       bool
	wallOps    bool
	server     *Server
	channels   ChannelSet
	atime      time.Time
}

type ClientSet map[*Client]bool

func NewClient(server *Server, conn net.Conn) *Client {
	client := &Client{
		channels: make(ChannelSet),
		conn:     conn,
		hostname: LookupHostname(conn.RemoteAddr()),
		recv:     StringReadChan(conn),
		server:   server,
	}
	client.SetReplyToStringChan()
	return client
}

func (c *Client) SetReplyToStringChan() {
	send := make(chan Reply)
	write := StringWriteChan(c.conn)
	go func() {
		for reply := range send {
			replyStr := reply.String(c)
			log.Printf("%s <- %s", c.Id(), replyStr)
			write <- replyStr
		}
	}()
	c.send = send
}

// Adapt `chan string` to a `chan Message`.
func (c *Client) Communicate() {
	for str := range c.recv {
		m, err := ParseMessage(str)
		if err != nil {
			// TODO handle error
			return
		}
		c.server.recv <- &ClientMessage{c, m}
	}
}

func (c *Client) Nick() string {
	if c.nick != "" {
		return c.nick
	}
	return "*"
}

func (c *Client) UModeString() string {
	if c.wallOps {
		return "+w"
	}
	return ""
}

func (c *Client) HasNick() bool {
	return c.nick != ""
}

func (c *Client) HasUser() bool {
	return c.username != ""
}

func (c *Client) Username() string {
	if c.HasUser() {
		return c.username
	}
	return "*"
}

func (c *Client) UserHost() string {
	return fmt.Sprintf("%s!%s@%s", c.Nick(), c.Username(), c.hostname)
}

func (c *Client) Id() string {
	return c.UserHost()
}
