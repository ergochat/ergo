package irc

import (
	"log"
	"net"
	"strings"
)

type Message struct {
	command string
	args    string
	client  *Client
}

type Client struct {
	addr       net.Addr
	send       chan string
	recv       chan string
	username   string
	realname   string
	nick       string
	registered bool
}

func NewClient(conn net.Conn) *Client {
	client := new(Client)
	client.addr = conn.RemoteAddr()
	client.send = StringWriteChan(conn)
	client.recv = StringReadChan(conn)
	return client
}

// Adapt `chan string` to a `chan Message`.
func (c *Client) Communicate(server *Server) {
	go func() {
		for str := range c.recv {
			parts := strings.SplitN(str, " ", 2)
			server.Send(Message{parts[0], parts[1], c})
		}
	}()
}

func (c *Client) Send(lines ...string) {
	for _, line := range lines {
		log.Printf("C <- S: %s", line)
		c.send <- line
	}
}

func (c *Client) Nick() string {
	if c.nick != "" {
		return c.nick
	}
	return "<guest>"
}
