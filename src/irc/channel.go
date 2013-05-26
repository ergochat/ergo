package irc

import (
	"log"
)

const (
	DEBUG_CHANNEL = true
)

type Channel struct {
	id        *RowId
	server    *Server
	commands  chan<- ChannelCommand
	replies   chan<- Reply
	name      string
	key       string
	topic     string
	members   UserSet
	noOutside bool
	password  string
}

type ChannelSet map[*Channel]bool

func (set ChannelSet) Add(channel *Channel) {
	set[channel] = true
}

func (set ChannelSet) Remove(channel *Channel) {
	delete(set, channel)
}

func (set ChannelSet) Ids() (ids []RowId) {
	ids = []RowId{}
	for channel := range set {
		if channel.id != nil {
			ids = append(ids, *channel.id)
		}
	}
	return ids
}

type ChannelCommand interface {
	Command
	HandleChannel(channel *Channel)
}

// NewChannel creates a new channel from a `Server` and a `name` string, which
// must be unique on the server.
func NewChannel(s *Server, name string) *Channel {
	commands := make(chan ChannelCommand, 1)
	replies := make(chan Reply, 1)
	channel := &Channel{
		name:     name,
		members:  make(UserSet),
		server:   s,
		commands: commands,
		replies:  replies,
	}
	go channel.receiveCommands(commands)
	go channel.receiveReplies(replies)
	return channel
}

func (channel *Channel) Save(q Queryable) bool {
	if channel.id == nil {
		if err := InsertChannel(q, channel); err != nil {
			return false
		}
		channelId, err := FindChannelIdByName(q, channel.name)
		if err != nil {
			return false
		}
		channel.id = &channelId
	} else {
		if err := UpdateChannel(q, channel); err != nil {
			return false
		}
	}
	return true
}

func (channel *Channel) receiveCommands(commands <-chan ChannelCommand) {
	for command := range commands {
		if DEBUG_CHANNEL {
			log.Printf("%s → %s : %s", command.Source(), channel, command)
		}
		command.HandleChannel(channel)
	}
}

func (channel *Channel) receiveReplies(replies <-chan Reply) {
	for reply := range replies {
		if DEBUG_CHANNEL {
			log.Printf("%s ← %s : %s", channel, reply.Source(), reply)
		}
		for user := range channel.members {
			if user != reply.Source() {
				user.Replies() <- reply
			}
		}
	}
}
func (channel *Channel) Nicks() []string {
	return channel.members.Nicks()
}

func (channel *Channel) IsEmpty() bool {
	return len(channel.members) == 0
}

func (channel *Channel) GetTopic(replier Replier) {
	if channel.topic == "" {
		replier.Replies() <- RplNoTopic(channel)
		return
	}

	replier.Replies() <- RplTopic(channel)
}

func (channel *Channel) Replies() chan<- Reply {
	return channel.replies
}

func (channel *Channel) Id() string {
	return channel.name
}

func (channel *Channel) PublicId() string {
	return channel.name
}

func (channel *Channel) Commands() chan<- ChannelCommand {
	return channel.commands
}

func (channel *Channel) String() string {
	return channel.Id()
}

//
// commands
//

func (m *JoinCommand) HandleChannel(channel *Channel) {
	client := m.Client()
	user := client.user

	if channel.key != m.channels[channel.name] {
		client.user.Replies() <- ErrBadChannelKey(channel)
		return
	}

	channel.members.Add(user)
	user.channels.Add(channel)

	channel.Replies() <- RplJoin(channel, user)
	channel.GetTopic(user)
	user.Replies() <- RplNamReply(channel)
	user.Replies() <- RplEndOfNames(channel.server)
}

func (m *PartCommand) HandleChannel(channel *Channel) {
	user := m.Client().user

	if !channel.members[user] {
		user.replies <- ErrNotOnChannel(channel)
		return
	}

	msg := m.message
	if msg == "" {
		msg = user.Nick()
	}

	channel.Replies() <- RplPart(channel, user, msg)

	channel.members.Remove(user)
	user.channels.Remove(channel)

	if channel.IsEmpty() {
		channel.server.DeleteChannel(channel)
	}
}

func (m *TopicCommand) HandleChannel(channel *Channel) {
	user := m.User()

	if !channel.members[user] {
		user.Replies() <- ErrNotOnChannel(channel)
		return
	}

	if m.topic == "" {
		channel.GetTopic(user)
		return
	}

	channel.topic = m.topic

	if channel.topic == "" {
		channel.Replies() <- RplNoTopic(channel)
		return
	}
	channel.Replies() <- RplTopic(channel)
}

func (m *PrivMsgCommand) HandleChannel(channel *Channel) {
	channel.Replies() <- RplPrivMsgChannel(channel, m.User(), m.message)
}
