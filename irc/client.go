package irc

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

type Client struct {
	away       bool
	channels   ChannelSet
	conn       net.Conn
	hostname   string
	idleTimer  *time.Timer
	invisible  bool
	nick       string
	operator   bool
	quitTimer  *time.Timer
	realname   string
	recv       *bufio.Reader
	registered bool
	replies    chan<- Reply
	send       *bufio.Writer
	server     *Server
	serverPass bool
	username   string
}

func NewClient(server *Server, conn net.Conn) *Client {
	replies := make(chan Reply)

	client := &Client{
		channels: make(ChannelSet),
		conn:     conn,
		hostname: AddrLookupHostname(conn.RemoteAddr()),
		recv:     bufio.NewReader(conn),
		replies:  replies,
		send:     bufio.NewWriter(conn),
		server:   server,
	}

	go client.readConn()
	go client.writeConn(replies)

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

func (c *Client) readConn() {
	for {
		line, err := c.recv.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("%s → %s error: %s", c.conn.RemoteAddr(), c.conn.LocalAddr(), err)
			}
			break
		}
		line = strings.TrimSpace(line)
		if DEBUG_NET {
			log.Printf("%s → %s %s", c.conn.RemoteAddr(), c.conn.LocalAddr(), line)
		}

		m, err := ParseCommand(line)
		if err != nil {
			if err == NotEnoughArgsError {
				c.Reply(ErrNeedMoreParams(c.server, line))
			} else {
				c.Reply(ErrUnknownCommand(c.server, line))
			}
			continue
		}

		m.SetClient(c)
		c.server.commands <- m
	}
}

func (client *Client) maybeLogWriteError(err error) bool {
	if err != nil {
		if err != io.EOF {
			log.Printf("%s ← %s error: %s", client.conn.RemoteAddr(), client.conn.LocalAddr(), err)
		}
		return true
	}
	return false
}

func (client *Client) writeConn(replies <-chan Reply) {
	for reply := range replies {
		if DEBUG_CLIENT {
			log.Printf("%s ← %s %s", client, reply.Source(), reply)
		}
		for _, str := range reply.Format(client) {
			if DEBUG_NET {
				log.Printf("%s ← %s %s", client.conn.RemoteAddr(), client.conn.LocalAddr(), str)
			}
			if _, err := client.send.WriteString(str); client.maybeLogWriteError(err) {
				break
			}
			if _, err := client.send.WriteString(CRLF); client.maybeLogWriteError(err) {
				break
			}
			if err := client.send.Flush(); client.maybeLogWriteError(err) {
				break
			}
		}
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

func (client *Client) Reply(replies ...Reply) error {
	if client.replies == nil {
		return ErrAlreadyDestroyed
	}
	for _, reply := range replies {
		client.replies <- reply
	}
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
