package irc

import (
	"code.google.com/p/go.crypto/bcrypt"
	"fmt"
	"log"
)

type UserCommand interface {
	Command
	HandleUser(*User)
}

type User struct {
	nick     string
	hash     []byte
	server   *Server
	clients  ClientSet
	channels ChannelSet
	commands chan<- UserCommand
	replies  chan<- Reply
}

type UserSet map[*User]bool

func (set UserSet) Add(user *User) {
	set[user] = true
}

func (set UserSet) Remove(user *User) {
	delete(set, user)
}

func NewUser(nick string, password string, server *Server) *User {
	commands := make(chan UserCommand)
	replies := make(chan Reply)
	user := &User{
		nick:     nick,
		server:   server,
		clients:  make(ClientSet),
		channels: make(ChannelSet),
		replies:  replies,
	}
	user.SetPassword(password)
	go user.receiveCommands(commands)
	go user.receiveReplies(replies)
	return user
}

func (user *User) SetPassword(password string) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic("bcrypt failed; cannot generate password hash")
	}
	user.hash = hash
}

func (user *User) receiveCommands(commands <-chan UserCommand) {
	for command := range commands {
		log.Printf("%s %T %+v", user.Id(), command, command)
		command.HandleUser(user)
	}
}

// Distribute replies to clients.
func (user *User) receiveReplies(replies <-chan Reply) {
	for reply := range replies {
		log.Printf("%s %T %+v", user.Id(), reply, reply)
		for client := range user.clients {
			client.Replies() <- reply
		}
	}
}

// Identifier

func (user User) Id() string {
	return fmt.Sprintf("%s!%s@%s", user.nick, user.nick, user.server.Id())
}

func (user User) PublicId() string {
	return user.Id()
}

func (user User) Nick() string {
	return user.nick
}

func (user User) Commands() chan<- UserCommand {
	return user.commands
}

func (user *User) Login(c *Client, nick string, password string) bool {
	if nick != c.nick {
		return false
	}

	if user.hash == nil {
		return false
	}

	err := bcrypt.CompareHashAndPassword(user.hash, []byte(password))
	if err != nil {
		c.Replies() <- ErrNoPrivileges(user.server)
		return false
	}

	user.clients[c] = true
	c.user = user
	for channel := range user.channels {
		channel.GetTopic(c)
		c.Replies() <- RplNamReply(channel)
		c.Replies() <- RplEndOfNames(channel.server)
	}
	return true
}

func (user *User) LogoutClient(c *Client) bool {
	if user.clients[c] {
		delete(user.clients, c)
		return true
	}
	return false
}

func (user User) HasClients() bool {
	return len(user.clients) > 0
}

func (user User) Replies() chan<- Reply {
	return user.replies
}

//
// commands
//

func (m *PrivMsgCommand) HandleUser(user *User) {
	user.Replies() <- RplPrivMsg(m.Client(), user, m.message)
}
