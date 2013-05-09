package irc

import (
	"log"
)

type Channel struct {
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

type ChannelCommand interface {
	Command
	HandleChannel(channel *Channel)
}

// NewChannel creates a new channel from a `Server` and a `name` string, which
// must be unique on the server.
func NewChannel(s *Server, name string) *Channel {
	replies := make(chan Reply)
	commands := make(chan ChannelCommand)
	channel := &Channel{
		name:     name,
		members:  make(UserSet),
		server:   s,
		commands: commands,
		replies:  replies,
	}
	go channel.receiveReplies(replies)
	go channel.receiveCommands(commands)
	return channel
}

// Forward `Reply`s to all `User`s of the `Channel`.
func (ch *Channel) receiveReplies(replies <-chan Reply) {
	for reply := range replies {
		for user := range ch.members {
			if user != reply.Source() {
				user.replies <- reply
			}
		}
	}
}

func (ch *Channel) receiveCommands(commands <-chan ChannelCommand) {
	for command := range commands {
		log.Printf("%s %T %+v", ch.Id(), command, command)
		command.HandleChannel(ch)
	}
}

func (ch *Channel) Nicks() []string {
	nicks := make([]string, len(ch.members))
	i := 0
	for member := range ch.members {
		nicks[i] = member.Nick()
		i++
	}
	return nicks
}

func (ch *Channel) IsEmpty() bool {
	return len(ch.members) == 0
}

func (channel *Channel) GetTopic(replier Replier) {
	if channel.topic == "" {
		replier.Replies() <- RplNoTopic(channel)
		return
	}

	replier.Replies() <- RplTopic(channel)
}

func (channel Channel) Id() string {
	return channel.name
}

func (channel Channel) PublicId() string {
	return channel.name
}

func (channel Channel) Commands() chan<- ChannelCommand {
	return channel.commands
}

//
// commands
//

func (m *JoinCommand) HandleChannel(channel *Channel) {
	client := m.Client()
	user := client.user

	if channel.key != m.channels[channel.name] {
		client.user.replies <- ErrBadChannelKey(channel)
		return
	}

	channel.members.Add(user)
	user.channels.Add(channel)

	channel.replies <- RplJoin(channel, user)
	channel.GetTopic(user)
	user.replies <- RplNamReply(channel)
	user.replies <- RplEndOfNames(channel.server)
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

	channel.replies <- RplPart(channel, user, msg)

	channel.members.Remove(user)
	user.channels.Remove(channel)

	if len(channel.members) == 0 {
		channel.server.DeleteChannel(channel)
	}
}

func (m *TopicCommand) HandleChannel(channel *Channel) {
	user := m.Client().user

	if !channel.members[user] {
		user.replies <- ErrNotOnChannel(channel)
		return
	}

	if m.topic == "" {
		channel.GetTopic(user)
		return
	}

	channel.topic = m.topic

	if channel.topic == "" {
		channel.replies <- RplNoTopic(channel)
		return
	}

	channel.replies <- RplTopic(channel)
}

func (m *PrivMsgCommand) HandleChannel(channel *Channel) {
	channel.replies <- RplPrivMsgChannel(channel, m.Client().user, m.message)
}
