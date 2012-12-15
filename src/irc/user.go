package irc

import (
	"code.google.com/p/go.crypto/bcrypt"
	"fmt"
)

type User struct {
	nick     string
	hash     []byte
	server   *Server
	replies  chan<- Reply
	commands <-chan Command
	clients  ClientSet
	channels ChannelSet
}

type UserSet map[*User]bool

func (set UserSet) Add(user *User) {
	set[user] = true
}

func (set UserSet) Remove(user *User) {
	delete(set, user)
}

func NewUser(nick string, password string, server *Server) *User {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic("bcrypt failed; cannot generate password hash")
	}
	replies := make(chan Reply)
	user := &User{
		nick:    nick,
		hash:    hash,
		server:  server,
		clients: make(ClientSet),
		replies: replies,
	}
	go user.receiveReplies(replies)
	return user
}

// Distribute replies to clients.
func (user *User) receiveReplies(replies <-chan Reply) {
	for reply := range replies {
		for client := range user.clients {
			client.replies <- reply
		}
	}
}

// Identifier

func (user *User) Id() string {
	return fmt.Sprintf("%s!%s@%s", user.nick, user.nick, user.server.Id())
}

func (user *User) PublicId() string {
	return user.Id()
}

func (user *User) Nick() string {
	return user.nick
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
		c.replies <- ErrNoPrivileges(user.server)
		return false
	}

	user.clients[c] = true
	c.user = user
	c.replies <- RplNick(c, user.nick)
	// TODO join channels
	return true
}

func (user *User) LogoutClient(c *Client) bool {
	if user.clients[c] {
		delete(user.clients, c)
		return true
	}
	return false
}

func (user *User) HasClients() bool {
	return len(user.clients) > 0
}
