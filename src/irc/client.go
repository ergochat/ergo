package irc

import (
	"net"
)

type Client struct {
	addr       net.Addr
	send       chan<- string
	recv       <-chan string
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
func (c *Client) Communicate(server chan<- *ClientMessage) {
	for str := range c.recv {
		m := ParseMessage(str)
		if m != nil {
			server <- &ClientMessage{c, m}
		}
	}
}

func (c *Client) Nick() string {
	if c.nick != "" {
		return c.nick
	}
	return "<guest>"
}
