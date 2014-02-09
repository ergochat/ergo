package irc

import (
	"log"
)

type Channel struct {
	banList   []UserMask
	commands  chan<- ChannelCommand
	key       string
	members   ClientSet
	name      string
	noOutside bool
	password  string
	replies   chan<- Reply
	server    *Server
	topic     string
}

func IsChannel(target string) bool {
	if target == "" {
		return false
	}
	switch target[0] {
	case '&', '#', '+', '!':
		return true
	}
	return false
}

// NewChannel creates a new channel from a `Server` and a `name`
// string, which must be unique on the server.
func NewChannel(s *Server, name string) *Channel {
	commands := make(chan ChannelCommand)
	replies := make(chan Reply)
	channel := &Channel{
		banList:  make([]UserMask, 0),
		commands: commands,
		members:  make(ClientSet),
		name:     name,
		replies:  replies,
		server:   s,
	}
	go channel.receiveCommands(commands)
	go channel.receiveReplies(replies)
	return channel
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
		for client := range channel.members {
			var dest Identifier = client
			if reply.Source() != dest {
				client.replies <- reply
			}
		}
	}
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

func (channel *Channel) GetUsers(replier Replier) {
	replier.Replies() <- NewNamesReply(channel)
}

func (channel *Channel) Nicks() []string {
	nicks := make([]string, len(channel.members))
	i := 0
	for client := range channel.members {
		nicks[i] = client.Nick()
		i += 1
	}
	return nicks
}

func (channel *Channel) Replies() chan<- Reply {
	return channel.replies
}

func (channel *Channel) Id() string {
	return channel.name
}

func (channel *Channel) Nick() string {
	return channel.name
}

func (channel *Channel) String() string {
	return channel.Id()
}

// <mode> <mode params>
func (channel *Channel) ModeString() string {
	return ""
}

func (channel *Channel) Join(client *Client) {
	channel.members.Add(client)
	client.channels.Add(channel)
	reply := RplJoin(client, channel)
	client.replies <- reply
	channel.replies <- reply
	channel.GetTopic(client)
	channel.GetUsers(client)
}

//
// commands
//

func (m *JoinCommand) HandleChannel(channel *Channel) {
	client := m.Client()
	if channel.key != m.channels[channel.name] {
		client.replies <- ErrBadChannelKey(channel)
		return
	}

	channel.Join(client)
}

func (m *PartCommand) HandleChannel(channel *Channel) {
	client := m.Client()

	if !channel.members.Has(client) {
		client.replies <- ErrNotOnChannel(channel)
		return
	}

	reply := RplPart(client, channel, m.Message())
	client.replies <- reply
	channel.replies <- reply

	channel.members.Remove(client)
	client.channels.Remove(channel)

	// TODO persistent channels
	if channel.IsEmpty() {
		channel.server.channels.Remove(channel)
	}
}

func (m *TopicCommand) HandleChannel(channel *Channel) {
	client := m.Client()

	if !channel.members.Has(client) {
		client.replies <- ErrNotOnChannel(channel)
		return
	}

	if m.topic == "" {
		channel.GetTopic(client)
		return
	}

	channel.topic = m.topic

	channel.GetTopic(channel)
}

func (m *PrivMsgCommand) HandleChannel(channel *Channel) {
	channel.replies <- RplPrivMsg(m.Client(), channel, m.message)
}

func (msg *ChannelModeCommand) HandleChannel(channel *Channel) {
	client := msg.Client()

	for _, modeOp := range msg.modeOps {
		switch modeOp.mode {
		case BanMask:
			// TODO add/remove
			for _, banMask := range channel.banList {
				client.replies <- RplBanList(channel, banMask)
			}
			client.replies <- RplEndOfBanList(channel)
		}
	}

	client.replies <- RplChannelModeIs(channel)
}
