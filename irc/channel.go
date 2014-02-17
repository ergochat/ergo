package irc

import (
	"log"
)

type Channel struct {
	banList []UserMask
	flags   ChannelModeSet
	key     string
	members MemberSet
	name    string
	server  *Server
	topic   string
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
	channel := &Channel{
		banList: make([]UserMask, 0),
		flags:   make(ChannelModeSet),
		members: make(MemberSet),
		name:    name,
		server:  s,
	}
	return channel
}

func (channel *Channel) Reply(reply Reply) {
	if DEBUG_CHANNEL {
		log.Printf("%s ← %s %s", channel, reply.Source(), reply)
	}

	for client := range channel.members {
		if (reply.Code() == ReplyCode(PRIVMSG)) &&
			(reply.Source() == Identifier(client)) {
			continue
		}
		client.Reply(reply)
	}
}

func (channel *Channel) IsEmpty() bool {
	return len(channel.members) == 0
}

func (channel *Channel) GetUsers(replier Replier) {
	replier.Reply(NewNamesReply(channel))
}

func (channel *Channel) ClientIsOperator(client *Client) bool {
	return client.flags[Operator] || channel.members.HasMode(client, ChannelOperator)
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

func (channel *Channel) Join(client *Client, key string) {
	if (channel.key != "") && (channel.key != key) {
		client.Reply(ErrBadChannelKey(channel))
		return
	}

	channel.members.Add(client)
	if len(channel.members) == 1 {
		channel.members[client][ChannelCreator] = true
		channel.members[client][ChannelOperator] = true
	}

	client.channels.Add(channel)

	for member := range channel.members {
		client.AddFriend(member)
		member.AddFriend(client)
	}

	channel.Reply(RplJoin(client, channel))
	channel.GetTopic(client)
	channel.GetUsers(client)
}

func (channel *Channel) Part(client *Client, message string) {
	if !channel.members.Has(client) {
		client.Reply(ErrNotOnChannel(channel))
		return
	}

	channel.Reply(RplPart(client, channel, message))
	channel.Quit(client)

	if channel.IsEmpty() {
		channel.server.channels.Remove(channel)
	}
}

func (channel *Channel) GetTopic(client *Client) {
	if !channel.members.Has(client) {
		client.Reply(ErrNotOnChannel(channel))
		return
	}

	if channel.topic == "" {
		// clients appear not to expect this
		//replier.Reply(RplNoTopic(channel))
		return
	}

	client.Reply(RplTopic(channel))
}

func (channel *Channel) SetTopic(client *Client, topic string) {
	if !channel.members.Has(client) {
		client.Reply(ErrNotOnChannel(channel))
		return
	}

	if channel.flags[OpOnlyTopic] && !channel.members[client][ChannelOperator] {
		client.Reply(ErrChanOPrivIsNeeded(channel))
		return
	}

	channel.topic = topic
	channel.Reply(RplTopicMsg(client, channel))
}

func (channel *Channel) PrivMsg(client *Client, message string) {
	if channel.flags[NoOutside] && !channel.members.Has(client) {
		client.Reply(ErrCannotSendToChan(channel))
		return
	}
	channel.Reply(RplPrivMsg(client, channel, message))
}

func (channel *Channel) Mode(client *Client, changes ChannelModeChanges) {
	if len(changes) == 0 {
		client.Reply(RplChannelModeIs(channel))
		return
	}

	applied := make(ChannelModeChanges, 0)

	for _, change := range changes {
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
				applied = append(applied, change)

			case Remove:
				delete(channel.flags, change.mode)
				applied = append(applied, change)
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
				applied = append(applied, change)

			case Remove:
				channel.key = ""
				applied = append(applied, change)
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
				applied = append(applied, change)

			case Remove:
				channel.members[target][change.mode] = false
				applied = append(applied, change)
			}
		}
	}

	if len(applied) > 0 {
		channel.Reply(RplChannelMode(client, channel, applied))
	}
}

func (channel *Channel) Notice(client *Client, message string) {
	if channel.flags[NoOutside] && !channel.members.Has(client) {
		client.Reply(ErrCannotSendToChan(channel))
		return
	}
	channel.Reply(RplNotice(client, channel, message))
}

func (channel *Channel) Quit(client *Client) {
	for member := range channel.members {
		client.RemoveFriend(member)
		member.RemoveFriend(client)
	}

	channel.members.Remove(client)
	client.channels.Remove(channel)
}

func (channel *Channel) Kick(client *Client, target *Client, comment string) {
	if !client.flags[Operator] && !channel.members.Has(client) {
		client.Reply(ErrNotOnChannel(channel))
		return
	}
	if !channel.ClientIsOperator(client) {
		client.Reply(ErrChanOPrivIsNeeded(channel))
		return
	}
	if !channel.members.Has(target) {
		client.Reply(ErrUserNotInChannel(channel, target))
		return
	}

	channel.Reply(RplKick(channel, client, target, comment))
	channel.Quit(target)
}
