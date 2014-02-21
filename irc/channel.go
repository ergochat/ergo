package irc

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
	return ChannelNameExpr.MatchString(target)
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

func (channel *Channel) IsEmpty() bool {
	return len(channel.members) == 0
}

func (channel *Channel) Names(client *Client) {
	client.MultilineReply(channel.Nicks(), RPL_NAMREPLY,
		"= %s :%s", channel.name)
	client.RplEndOfNames(channel)
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
		client.ErrBadChannelKey(channel)
		return
	}

	if channel.members[client] != nil {
		// already joined, no message?
		return
	}

	client.channels.Add(channel)
	channel.members.Add(client)
	if len(channel.members) == 1 {
		channel.members[client][ChannelCreator] = true
		channel.members[client][ChannelOperator] = true
	}

	reply := RplJoin(client, channel)
	for member := range channel.members {
		member.replies <- reply
	}
	channel.GetTopic(client)
	channel.Names(client)
}

func (channel *Channel) Part(client *Client, message string) {
	if !channel.members.Has(client) {
		client.ErrNotOnChannel(channel)
		return
	}

	reply := RplPart(client, channel, message)
	for member := range channel.members {
		member.replies <- reply
	}
	channel.Quit(client)

	if channel.IsEmpty() {
		channel.server.channels.Remove(channel)
	}
}

func (channel *Channel) GetTopic(client *Client) {
	if !channel.members.Has(client) {
		client.ErrNotOnChannel(channel)
		return
	}

	if channel.topic == "" {
		// clients appear not to expect this
		//replier.Reply(RplNoTopic(channel))
		return
	}

	client.RplTopic(channel)
}

func (channel *Channel) SetTopic(client *Client, topic string) {
	if !channel.members.Has(client) {
		client.ErrNotOnChannel(channel)
		return
	}

	if channel.flags[OpOnlyTopic] && !channel.members[client][ChannelOperator] {
		client.ErrChanOPrivIsNeeded(channel)
		return
	}

	channel.topic = topic
	for member := range channel.members {
		member.replies <- RplTopicMsg(client, channel)
	}
}

func (channel *Channel) PrivMsg(client *Client, message string) {
	if channel.flags[NoOutside] && !channel.members.Has(client) {
		client.ErrCannotSendToChan(channel)
		return
	}
	for member := range channel.members {
		if member == client {
			continue
		}
		member.replies <- RplPrivMsg(client, channel, message)
	}
}

func (channel *Channel) Mode(client *Client, changes ChannelModeChanges) {
	if len(changes) == 0 {
		client.RplChannelModeIs(channel)
		return
	}

	applied := make(ChannelModeChanges, 0)

	for _, change := range changes {
		switch change.mode {
		case BanMask:
			// TODO add/remove

			for _, banMask := range channel.banList {
				client.RplBanList(channel, banMask)
			}
			client.RplEndOfBanList(channel)

		case NoOutside, Private, Secret, OpOnlyTopic:
			if !channel.ClientIsOperator(client) {
				client.ErrChanOPrivIsNeeded(channel)
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
				client.ErrChanOPrivIsNeeded(channel)
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
				client.ErrChanOPrivIsNeeded(channel)
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
		for member := range channel.members {
			member.replies <- RplChannelMode(client, channel, applied)
		}
	}
}

func (channel *Channel) Notice(client *Client, message string) {
	if channel.flags[NoOutside] && !channel.members.Has(client) {
		client.ErrCannotSendToChan(channel)
		return
	}
	for member := range channel.members {
		if member == client {
			continue
		}
		member.replies <- RplNotice(client, channel, message)
	}
}

func (channel *Channel) Quit(client *Client) {
	channel.members.Remove(client)
	client.channels.Remove(channel)
}

func (channel *Channel) Kick(client *Client, target *Client, comment string) {
	if !client.flags[Operator] && !channel.members.Has(client) {
		client.ErrNotOnChannel(channel)
		return
	}
	if !channel.ClientIsOperator(client) {
		client.ErrChanOPrivIsNeeded(channel)
		return
	}
	if !channel.members.Has(target) {
		client.ErrUserNotInChannel(channel, target)
		return
	}

	for member := range channel.members {
		member.replies <- RplKick(channel, client, target, comment)
	}
	channel.Quit(target)
}
