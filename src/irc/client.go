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
	read := StringReadChan(conn)
	write := StringWriteChan(conn)
	send := make(chan Reply)

	client := &Client{
		channels: make(ChannelSet),
		conn:     conn,
		hostname: LookupHostname(conn.RemoteAddr()),
		server:   server,
		send:     send,
	}

	// Connect the conn to the server.
	go client.readConn(read)

	// Connect the reply channel to the conn.
	go client.writeConn(write, send)

	return client
}

func (c *Client) readConn(recv <-chan string) {
	for str := range recv {
		log.Printf("%s > %s", c.Id(), str)

		m, err := ParseMessage(str)
		if err != nil {
			// TODO handle error
			continue
		}

		m.SetClient(c)
		c.server.recv <- m
	}
}

func (c *Client) writeConn(write chan<- string, send <-chan Reply) {
	for reply := range send {
		replyStr := reply.String(c)
		log.Printf("%s < %s", c.Id(), replyStr)
		write <- replyStr
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
