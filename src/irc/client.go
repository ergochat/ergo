package irc

import (
	"fmt"
	"log"
	"net"
	"time"
)

const (
	DEBUG_CLIENT = true
)

type Client struct {
	conn       net.Conn
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
	replies    chan<- Reply
}

type ClientSet map[*Client]bool

func NewClient(server *Server, conn net.Conn) *Client {
	read := StringReadChan(conn)
	write := StringWriteChan(conn)
	replies := make(chan Reply, 1)

	client := &Client{
		conn:     conn,
		hostname: conn.RemoteAddr().String(),
		server:   server,
		replies:  replies,
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
				c.Replies() <- ErrNeedMoreParams(c.server, str)
			} else {
				c.Replies() <- ErrUnknownCommand(c.server, str)
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
			log.Printf("%s ← %s : %s", c, reply.Source(), reply)
		}
		write <- reply.Format(c)
	}
}

func (c *Client) Replies() chan<- Reply {
	return c.replies
}

func (c *Client) Server() *Server {
	return c.server
}

func (c *Client) Nick() string {
	if c.user != nil {
		return c.user.Nick()
	}

	if c.nick != "" {
		return c.nick
	}

	return "guest"
}

func (c *Client) UModeString() string {
	return ""
}

func (c *Client) HasNick() bool {
	return c.Nick() != ""
}

func (c *Client) HasUsername() bool {
	return c.username != ""
}

func (c *Client) Username() string {
	if c.HasUsername() {
		return c.username
	}
	return "guest"
}

func (c *Client) UserHost() string {
	return fmt.Sprintf("%s!%s@%s", c.Nick(), c.Username(), c.hostname)
}

func (c *Client) Id() string {
	return c.UserHost()
}

func (c *Client) String() string {
	return c.hostname
}

func (c *Client) PublicId() string {
	return fmt.Sprintf("%s!%s@%s", c.Nick(), c.Nick(), c.server.Id())
}
