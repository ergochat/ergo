package irc

import (
	"fmt"
	"log"
	"net"
	"time"
)

type Client struct {
	conn       net.Conn
	replies    chan<- Reply
	username   string
	realname   string
	hostname   string
	nick       string
	serverPass bool
	registered bool
	away       bool
	server     *Server
	atime      time.Time
	user       *User
}

type ClientSet map[*Client]bool

func NewClient(server *Server, conn net.Conn) *Client {
	read := StringReadChan(conn)
	write := StringWriteChan(conn)
	replies := make(chan Reply)

	client := &Client{
		conn:     conn,
		hostname: LookupHostname(conn.RemoteAddr()),
		server:   server,
		replies:  replies,
	}

	// Connect the conn to the server.
	go client.readConn(read)

	// Connect the reply channel to the conn.
	go client.writeConn(write, replies)

	return client
}

func (c *Client) readConn(recv <-chan string) {
	for str := range recv {
		log.Printf("%s > %s", c.Id(), str)

		m, err := ParseCommand(str)
		if err != nil {
			// TODO handle error
			continue
		}

		m.SetClient(c)
		c.server.commands <- m
	}
}

func (c *Client) writeConn(write chan<- string, replies <-chan Reply) {
	for reply := range replies {
		replyStr := reply.String(c)
		log.Printf("%s < %s", c.Id(), replyStr)
		write <- replyStr
	}
}

func (c *Client) Nick() string {
	if c.user != nil {
		return c.user.nick
	}

	if c.nick != "" {
		return c.nick
	}

	return "*"
}

func (c *Client) UModeString() string {
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

func (c *Client) PublicId() string {
	return fmt.Sprintf("%s!%s@%s", c.Nick(), c.Nick(), c.server.Id())
}
