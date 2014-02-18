package irc

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

func IsNickname(nick string) bool {
	return NicknameExpr.MatchString(nick)
}

type Client struct {
	atime       time.Time
	awayMessage string
	channels    ChannelSet
	ctime       time.Time
	flags       map[UserMode]bool
	friends     map[*Client]uint
	hops        uint
	hostname    string
	idleTimer   *time.Timer
	loginTimer  *time.Timer
	nick        string
	phase       Phase
	quitTimer   *time.Timer
	realname    string
	server      *Server
	socket      *Socket
	username    string
}

func NewClient(server *Server, conn net.Conn) *Client {
	now := time.Now()
	client := &Client{
		atime:    now,
		channels: make(ChannelSet),
		ctime:    now,
		flags:    make(map[UserMode]bool),
		friends:  make(map[*Client]uint),
		hostname: AddrLookupHostname(conn.RemoteAddr()),
		phase:    server.InitPhase(),
		server:   server,
		socket:   NewSocket(conn),
	}

	client.loginTimer = time.AfterFunc(LOGIN_TIMEOUT, client.connectionClosed)
	go client.readCommands()

	return client
}

func (client *Client) readCommands() {
	for line := range client.socket.Read() {
		msg, err := ParseCommand(line)
		if err != nil {
			switch err {
			case NotEnoughArgsError:
				parts := strings.SplitN(line, " ", 2)
				client.Reply(ErrNeedMoreParams(client.server, parts[0]))
			}
			continue
		}

		msg.SetClient(client)
		client.server.commands <- msg
	}

	client.server.toDestroy <- client
}

func (client *Client) Touch() {
	client.atime = time.Now()

	if client.quitTimer != nil {
		client.quitTimer.Stop()
	}

	if client.idleTimer == nil {
		client.idleTimer = time.AfterFunc(IDLE_TIMEOUT, client.Idle)
	} else {
		client.idleTimer.Reset(IDLE_TIMEOUT)
	}
}

type ClientIdle struct {
	BaseCommand
}

func (client *Client) Idle() {
	if client.quitTimer == nil {
		client.quitTimer = time.AfterFunc(QUIT_TIMEOUT, client.connectionTimeout)
	} else {
		client.quitTimer.Reset(QUIT_TIMEOUT)
	}

	cmd := &ClientIdle{}
	cmd.SetClient(client)
	client.server.commands <- cmd
}

func (client *Client) connectionTimeout() {
	msg := &QuitCommand{
		message: "connection timeout",
	}
	msg.SetClient(client)
	client.server.commands <- msg
}

func (client *Client) connectionClosed() {
	msg := &QuitCommand{
		message: "connection closed",
	}
	msg.SetClient(client)
	client.server.commands <- msg
}

func (client *Client) Destroy() {
	if DEBUG_CLIENT {
		log.Printf("%s: destroying", client)
	}
	// clean up self

	client.socket.Close()

	client.loginTimer.Stop()
	if client.idleTimer != nil {
		client.idleTimer.Stop()
	}
	if client.quitTimer != nil {
		client.quitTimer.Stop()
	}

	// clean up channels

	for channel := range client.channels {
		channel.Quit(client)
	}

	// clean up server

	client.server.clients.Remove(client)

	if DEBUG_CLIENT {
		log.Printf("%s: destroyed", client)
	}
}

func (client *Client) Reply(reply Reply) {
	client.socket.Write(reply.Format(client)...)
}

func (client *Client) IdleTime() time.Duration {
	return time.Since(client.atime)
}

func (client *Client) SignonTime() int64 {
	return client.ctime.Unix()
}

func (client *Client) IdleSeconds() uint64 {
	return uint64(client.IdleTime().Seconds())
}

func (client *Client) HasNick() bool {
	return client.nick != ""
}

func (client *Client) HasUsername() bool {
	return client.username != ""
}

// <mode>
func (c *Client) ModeString() (str string) {
	for flag := range c.flags {
		str += flag.String()
	}

	if len(str) > 0 {
		str = "+" + str
	}
	return
}

func (c *Client) UserHost() string {
	username := "*"
	if c.HasUsername() {
		username = c.username
	}
	return fmt.Sprintf("%s!%s@%s", c.Nick(), username, c.hostname)
}

func (c *Client) Nick() string {
	if c.HasNick() {
		return c.nick
	}
	return "*"
}

func (c *Client) Id() string {
	return c.UserHost()
}

func (c *Client) String() string {
	return c.Id()
}

func (client *Client) AddFriend(friend *Client) {
	client.friends[friend] += 1
}

func (client *Client) RemoveFriend(friend *Client) {
	client.friends[friend] -= 1
	if client.friends[friend] <= 0 {
		delete(client.friends, friend)
	}
}

func (client *Client) ChangeNickname(nickname string) {
	// Make reply before changing nick.
	reply := RplNick(client, nickname)

	client.nick = nickname

	for friend := range client.friends {
		friend.Reply(reply)
	}
}

func (client *Client) Quit(message string) {
	if len(client.friends) > 0 {
		reply := RplQuit(client, message)
		for friend := range client.friends {
			if friend == client {
				continue
			}
			friend.Reply(reply)
		}
	}

	client.Reply(RplError(client.server, client))
	client.socket.Close()
}
