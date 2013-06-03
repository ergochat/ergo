package irc

import (
	"code.google.com/p/go.crypto/bcrypt"
	"fmt"
	"log"
)

const (
	DEBUG_USER = true
)

type UserCommand interface {
	Command
	HandleUser(*User)
}

type User struct {
	id       RowId
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

func (set UserSet) Nicks() []string {
	nicks := make([]string, len(set))
	i := 0
	for member := range set {
		nicks[i] = member.Nick()
		i++
	}
	return nicks
}

func NewUser(nick string, server *Server) *User {
	commands := make(chan UserCommand)
	replies := make(chan Reply)
	user := &User{
		nick:     nick,
		server:   server,
		clients:  make(ClientSet),
		channels: make(ChannelSet),
		replies:  replies,
	}

	go user.receiveCommands(commands)
	go user.receiveReplies(replies)
	server.users[nick] = user

	return user
}

func (user *User) Row() *UserRow {
	return &UserRow{user.id, user.nick, user.hash}
}

func (user *User) Create(q Queryable) bool {
	var err error
	if err := InsertUser(q, user.Row()); err != nil {
		log.Println(err)
		return false
	}
	user.id, err = FindUserIdByNick(q, user.nick)
	if err != nil {
		log.Println(err)
		return false
	}
	return true
}

func (user *User) Save(q Queryable) bool {
	if err := UpdateUser(q, user.Row()); err != nil {
		log.Println(err)
		return false
	}

	channelIds := user.channels.Ids()
	if len(channelIds) == 0 {
		if err := DeleteAllUserChannels(q, user.id); err != nil {
			log.Println(err)
			return false
		}
	} else {
		if err := DeleteOtherUserChannels(q, user.id, channelIds); err != nil {
			log.Println(err)
			return false
		}
		if err := InsertUserChannels(q, user.id, channelIds); err != nil {
			log.Println(err)
			return false
		}
	}
	return true
}

func (user *User) Delete(q Queryable) bool {
	err := DeleteUser(q, user.id)
	if err != nil {
		log.Println(err)
		return false
	}
	return true
}

func (user *User) Load(q Queryable) bool {
	crs, err := FindChannelsForUser(q, user.id)
	if err != nil {
		log.Println(err)
		return false
	}
	for _, cr := range crs {
		user.server.GetOrMakeChannel(cr.name).Join(user)
	}
	return true
}

func (user *User) SetPassword(password string) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Panicln(err)
	}
	user.SetHash(hash)
}

func (user *User) SetHash(hash []byte) {
	user.hash = hash
}

func (user *User) receiveCommands(commands <-chan UserCommand) {
	for command := range commands {
		if DEBUG_USER {
			log.Printf("%s → %s : %s", command.Client(), user, command)
		}
		command.HandleUser(user)
	}
}

// Distribute replies to clients.
func (user *User) receiveReplies(replies <-chan Reply) {
	for reply := range replies {
		if DEBUG_USER {
			log.Printf("%s ← %s : %s", user, reply.Source(), reply)
		}
		for client := range user.clients {
			client.Replies() <- reply
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

func (user *User) String() string {
	return user.Id()
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
		channel.GetUsers(c)
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

func (user *User) HasClients() bool {
	return len(user.clients) > 0
}

func (user *User) Replies() chan<- Reply {
	return user.replies
}

//
// commands
//

func (m *PrivMsgCommand) HandleUser(user *User) {
	user.Replies() <- RplPrivMsg(m.Client(), user, m.message)
}
