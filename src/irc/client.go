package irc

import (
	"net"
)


type Client struct {
	conn net.Conn
	ch chan Message
}

func NewClient(conn net.Conn) *Client {
	return &Client{conn, NewMessageChan(NewStringChan(conn))}
}

// Write messages from the client to the server.
func (c *Client) Communicate(server chan Message) {
	for message := range c.ch {
		message.client = c
		server <- message
	}
	c.Close()
}

func (c *Client) Close() {
	c.conn.Close()
}
