package irc

import (
	"log"
)

type Channel struct {
	banList   []UserMask
	commands  chan<- ChannelCommand
	destroyed bool
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

func (channel *Channel) Destroy() {
	if channel.destroyed {
		return
	}

	close(channel.replies)
	channel.replies = nil
	close(channel.commands)
	channel.commands = nil

	channel.server.channels.Remove(channel)

	channel.destroyed = true
}

func (channel *Channel) Command(command ChannelCommand) {
	if channel.commands == nil {
		return
	}
	channel.commands <- command
}

func (channel *Channel) Reply(replies ...Reply) {
	if channel.replies == nil {
		return
	}
	for _, reply := range replies {
		channel.replies <- reply
	}
}

func (channel *Channel) receiveCommands(commands <-chan ChannelCommand) {
	for command := range commands {
		if DEBUG_CHANNEL {
			log.Printf("%s → %s %s", command.Source(), channel, command)
		}
		command.HandleChannel(channel)
	}
}

func (channel *Channel) receiveReplies(replies <-chan Reply) {
	for reply := range replies {
		if DEBUG_CHANNEL {
			log.Printf("%s ← %s %s", channel, reply.Source(), reply)
		}
		for client := range channel.members {
			if reply.Source() != Identifier(client) {
				client.Reply(reply)
			}
		}
	}
}

func (channel *Channel) IsEmpty() bool {
	return len(channel.members) == 0
}

func (channel *Channel) GetTopic(replier Replier) {
	if channel.topic == "" {
		replier.Reply(RplNoTopic(channel))
		return
	}

	replier.Reply(RplTopic(channel))
}

func (channel *Channel) GetUsers(replier Replier) {
	replier.Reply(NewNamesReply(channel))
}

func (channel *Channel) ClientIsOperator(client *Client) bool {
	// TODO client-channel relations
	return false
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
func (channel *Channel) ModeString() (str string) {
	if channel.noOutside {
		str += NoOutside.String()
	}
	if len(str) > 0 {
		str = "+" + str
	}
	return
}

func (channel *Channel) Join(client *Client) {
	channel.members.Add(client)
	client.channels.Add(channel)
	reply := RplJoin(client, channel)
	client.Reply(reply)
	channel.Reply(reply)
	channel.GetTopic(client)
	channel.GetUsers(client)
}

//
// commands
//

func (m *JoinCommand) HandleChannel(channel *Channel) {
	client := m.Client()
	if channel.key != m.channels[channel.name] {
		client.Reply(ErrBadChannelKey(channel))
		return
	}

	channel.Join(client)
}

func (m *PartCommand) HandleChannel(channel *Channel) {
	client := m.Client()

	if !channel.members.Has(client) {
		client.Reply(ErrNotOnChannel(channel))
		return
	}

	reply := RplPart(client, channel, m.Message())
	client.Reply(reply)
	channel.Reply(reply)

	channel.members.Remove(client)
	client.channels.Remove(channel)

	// TODO persistent channels
	if channel.IsEmpty() {
		channel.Destroy()
	}
}

func (m *TopicCommand) HandleChannel(channel *Channel) {
	client := m.Client()

	if !channel.members.Has(client) {
		client.Reply(ErrNotOnChannel(channel))
		return
	}

	if m.setTopic {
		channel.topic = m.topic
		channel.GetTopic(client)
		reply := RplTopicMsg(client, channel)
		client.Reply(reply)
		channel.Reply(reply)
		return
	}

	channel.GetTopic(client)
	return
}

func (m *PrivMsgCommand) HandleChannel(channel *Channel) {
	client := m.Client()
	if channel.noOutside && !channel.members.Has(client) {
		client.Reply(ErrCannotSendToChan(channel))
		return
	}
	channel.Reply(RplPrivMsg(client, channel, m.message))
}

func (msg *ChannelModeCommand) HandleChannel(channel *Channel) {
	client := msg.Client()

	for _, modeOp := range msg.modeOps {
		switch modeOp.mode {
		case BanMask:
			// TODO add/remove
			for _, banMask := range channel.banList {
				client.Reply(RplBanList(channel, banMask))
			}
			client.Reply(RplEndOfBanList(channel))
		case NoOutside:
			if channel.ClientIsOperator(client) {
				switch modeOp.op {
				case Add:
					channel.noOutside = true
				case Remove:
					channel.noOutside = false
				}
			} else {
				client.Reply(ErrChanOPrivIsNeeded(channel))
			}
		}
	}

	client.Reply(RplChannelModeIs(channel))
}

func (m *NoticeCommand) HandleChannel(channel *Channel) {
	client := m.Client()
	if channel.noOutside && !channel.members.Has(client) {
		client.Reply(ErrCannotSendToChan(channel))
		return
	}
	channel.Reply(RplNotice(client, channel, m.message))
}
