package irc

import (
	"log"
	"sync"
)

type Channel struct {
	banList   []UserMask
	commands  chan<- ChannelCommand
	destroyed bool
	flags     map[ChannelMode]bool
	key       string
	members   ClientSet
	mutex     *sync.Mutex
	name      string
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
		flags:    make(map[ChannelMode]bool),
		members:  make(ClientSet),
		mutex:    &sync.Mutex{},
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

	channel.destroyed = true
	channel.members = make(ClientSet)
	channel.server.channels.Remove(channel)
}

func (channel *Channel) Command(command ChannelCommand) {
	channel.commands <- command
}

func (channel *Channel) Reply(reply Reply) {
	channel.replies <- reply
}

func (channel *Channel) receiveCommands(commands <-chan ChannelCommand) {
	for command := range commands {
		if channel.destroyed {
			if DEBUG_CHANNEL {
				log.Printf("%s → %s %s dropped", command.Source(), channel, command)
			}
			continue
		}

		if DEBUG_CHANNEL {
			log.Printf("%s → %s %s", command.Source(), channel, command)
		}
		command.HandleChannel(channel)
	}
}

func IsPrivMsg(reply Reply) bool {
	strReply, ok := reply.(*StringReply)
	if !ok {
		return false
	}
	return strReply.code == "PRIVMSG"
}

func (channel *Channel) receiveReplies(replies <-chan Reply) {
	for reply := range replies {
		if channel.destroyed {
			if DEBUG_CHANNEL {
				log.Printf("%s ← %s %s dropped", channel, reply.Source(), reply)
			}
			continue
		}

		if DEBUG_CHANNEL {
			log.Printf("%s ← %s %s", channel, reply.Source(), reply)
		}
		channel.mutex.Lock()
		for client := range channel.members {
			if IsPrivMsg(reply) && (reply.Source() == Identifier(client)) {
				continue
			}
			client.Reply(reply)
		}
		channel.mutex.Unlock()
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
	return channel.members.HasMode(client, ChannelOperator)
}

func (channel *Channel) Nicks() []string {
	nicks := make([]string, len(channel.members))
	i := 0
	for client, modes := range channel.members {
		switch {
		case modes[ChannelOperator]:
			nicks[i] = "@" + client.Nick()
		case modes[Voice]:
			nicks[i] = "+" + client.Nick()
		default:
			nicks[i] = client.Nick()
		}
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
	if channel.key != "" {
		str += Key.String()
	}

	for mode := range channel.flags {
		str += mode.String()
	}

	if len(str) > 0 {
		str = "+" + str
	}

	if channel.key != "" {
		str += " " + channel.key
	}

	return
}

func (channel *Channel) withMutex(f func()) {
	channel.mutex.Lock()
	defer channel.mutex.Unlock()
	f()
}

func (channel *Channel) Join(client *Client) {
	channel.withMutex(func() {
		channel.members.Add(client)
		if len(channel.members) == 1 {
			channel.members[client][ChannelCreator] = true
			channel.members[client][ChannelOperator] = true
		}
		client.channels.Add(channel)
	})

	channel.Reply(RplJoin(client, channel))
	channel.GetTopic(client)
	channel.GetUsers(client)
}

//
// commands
//

func (m *JoinCommand) HandleChannel(channel *Channel) {
	client := m.Client()
	if (channel.key != "") && (channel.key != m.channels[channel.name]) {
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

	channel.Reply(RplPart(client, channel, m.Message()))

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

	if !m.setTopic {
		channel.GetTopic(client)
		return
	}

	if channel.flags[OpOnlyTopic] {
		client.Reply(ErrChanOPrivIsNeeded(channel))
		return
	}

	channel.topic = m.topic
	channel.Reply(RplTopicMsg(client, channel))
}

func (m *PrivMsgCommand) HandleChannel(channel *Channel) {
	client := m.Client()
	if channel.flags[NoOutside] && !channel.members.Has(client) {
		client.Reply(ErrCannotSendToChan(channel))
		return
	}
	channel.Reply(RplPrivMsg(client, channel, m.message))
}

func (msg *ChannelModeCommand) HandleChannel(channel *Channel) {
	client := msg.Client()

	if len(msg.changes) == 0 {
		client.Reply(RplChannelModeIs(channel))
		return
	}

	changes := make(ChannelModeChanges, 0)

	for _, change := range msg.changes {
		switch change.mode {
		case BanMask:
			// TODO add/remove

			for _, banMask := range channel.banList {
				client.Reply(RplBanList(channel, banMask))
			}
			client.Reply(RplEndOfBanList(channel))

		case NoOutside, Private, Secret, OpOnlyTopic:
			if !channel.ClientIsOperator(client) {
				client.Reply(ErrChanOPrivIsNeeded(channel))
				continue
			}

			switch change.op {
			case Add:
				channel.flags[change.mode] = true
				changes = append(changes, change)

			case Remove:
				delete(channel.flags, change.mode)
				changes = append(changes, change)
			}

		case Key:
			if !channel.ClientIsOperator(client) {
				client.Reply(ErrChanOPrivIsNeeded(channel))
				continue
			}

			switch change.op {
			case Add:
				if change.arg == "" {
					// TODO err reply
					continue
				}

				channel.key = change.arg
				changes = append(changes, change)

			case Remove:
				channel.key = ""
				changes = append(changes, change)
			}

		case ChannelOperator, Voice:
			if !channel.ClientIsOperator(client) {
				client.Reply(ErrChanOPrivIsNeeded(channel))
				continue
			}

			if change.arg == "" {
				// TODO err reply
				continue
			}

			target := channel.server.clients[change.arg]
			if target == nil {
				// TODO err reply
				continue
			}

			if channel.members[target] == nil {
				// TODO err reply
				continue
			}

			switch change.op {
			case Add:
				channel.members[target][change.mode] = true
				changes = append(changes, change)

			case Remove:
				channel.members[target][change.mode] = false
				changes = append(changes, change)
			}
		}
	}

	if len(changes) > 0 {
		channel.Reply(RplChannelMode(client, channel, changes))
	}
}

func (m *NoticeCommand) HandleChannel(channel *Channel) {
	client := m.Client()
	if channel.flags[NoOutside] && !channel.members.Has(client) {
		client.Reply(ErrCannotSendToChan(channel))
		return
	}
	channel.Reply(RplNotice(client, channel, m.message))
}
