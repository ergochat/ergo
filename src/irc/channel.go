package irc

type Channel struct {
	server    *Server
	replies   chan<- Reply
	commands  chan<- ChannelCommand
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

type JoinChannelCommand struct {
	*JoinCommand
	key string
}

type PartChannelCommand struct {
	Command
	message string
}

type GetTopicChannelCommand struct {
	*TopicCommand
}

type SetTopicChannelCommand struct {
	*TopicCommand
}

type PrivMsgChannelCommand struct {
	*PrivMsgCommand
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
		for client := range ch.members {
			client.replies <- reply
		}
	}
}

func (ch *Channel) receiveCommands(commands <-chan ChannelCommand) {
	for command := range commands {
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

//
// commands
//

func (m *JoinChannelCommand) HandleChannel(channel *Channel) {
	client := m.Client()
	user := client.user

	if channel.key != m.key {
		client.user.replies <- ErrBadChannelKey(channel)
		return
	}

	channel.members.Add(client.user)
	client.user.channels.Add(channel)

	channel.replies <- RplJoin(channel, user)
	channel.GetTopic(user)
	client.user.replies <- RplNamReply(channel)
	client.user.replies <- RplEndOfNames(channel.server)
}

func (m *PartChannelCommand) HandleChannel(channel *Channel) {
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

func (channel *Channel) GetTopic(user *User) {
	if !channel.members[user] {
		user.replies <- ErrNotOnChannel(channel)
		return
	}

	if channel.topic == "" {
		user.replies <- RplNoTopic(channel)
		return
	}

	user.replies <- RplTopic(channel)
}

func (m *GetTopicChannelCommand) HandleChannel(channel *Channel) {
	channel.GetTopic(m.Client().user)
}

func (m *SetTopicChannelCommand) HandleChannel(channel *Channel) {
	user := m.Client().user

	if !channel.members[user] {
		user.replies <- ErrNotOnChannel(channel)
		return
	}

	channel.topic = m.topic

	if channel.topic == "" {
		channel.replies <- RplNoTopic(channel)
		return
	}

	channel.replies <- RplTopic(channel)
}

func (m *PrivMsgChannelCommand) HandleChannel(channel *Channel) {
	channel.replies <- RplPrivMsgChannel(channel, m.Client().user, m.message)
}
