package irc

import (
	"strconv"
)

type Channel struct {
	flags     ChannelModeSet
	lists     map[ChannelMode][]UserMask
	key       string
	members   MemberSet
	name      string
	server    *Server
	topic     string
	userLimit uint64
}

func IsChannel(target string) bool {
	return ChannelNameExpr.MatchString(target)
}

// NewChannel creates a new channel from a `Server` and a `name`
// string, which must be unique on the server.
func NewChannel(s *Server, name string) *Channel {
	channel := &Channel{
		flags: make(ChannelModeSet),
		lists: map[ChannelMode][]UserMask{
			BanMask:    []UserMask{},
			ExceptMask: []UserMask{},
			InviteMask: []UserMask{},
		},
		members: make(MemberSet),
		name:    name,
		server:  s,
	}

	s.channels[name] = channel
	s.db.Exec(`INSERT INTO channel
                 (name, flags, key, topic, user_limit)
                 VALUES (?, ?, ?, ?, ?)`,
		channel.name, channel.flags.String(), channel.key, channel.topic,
		channel.userLimit)

	return channel
}

func (channel *Channel) IsEmpty() bool {
	return len(channel.members) == 0
}

func (channel *Channel) Names(client *Client) {
	client.RplNamReply(channel)
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
func (channel *Channel) ModeString(client *Client) (str string) {
	isMember := client.flags[Operator] || channel.members.Has(client)
	showKey := isMember && (channel.key != "")
	showUserLimit := channel.userLimit > 0

	// flags with args
	if showKey {
		str += Key.String()
	}
	if showUserLimit {
		str += UserLimit.String()
	}

	// flags
	for mode := range channel.flags {
		str += mode.String()
	}

	if len(str) > 0 {
		str = "+" + str
	}

	// args for flags with args: The order must match above to keep
	// positional arguments in place.
	if showKey {
		str += " " + channel.key
	}
	if showUserLimit {
		str += " " + strconv.FormatUint(channel.userLimit, 10)
	}

	return
}

func (channel *Channel) IsFull() bool {
	return (channel.userLimit > 0) &&
		(uint64(len(channel.members)) >= channel.userLimit)
}

func (channel *Channel) CheckKey(key string) bool {
	return (channel.key == "") || (channel.key == key)
}

func (channel *Channel) Join(client *Client, key string) {
	if channel.members.Has(client) {
		// already joined, no message?
		return
	}

	if channel.IsFull() {
		client.ErrChannelIsFull(channel)
		return
	}

	if !channel.CheckKey(key) {
		client.ErrBadChannelKey(channel)
		return
	}

	client.channels.Add(channel)
	channel.members.Add(client)
	if len(channel.members) == 1 {
		if !channel.flags[Persistent] {
			channel.members[client][ChannelCreator] = true
		}
		channel.members[client][ChannelOperator] = true
	}

	reply := RplJoin(client, channel)
	for member := range channel.members {
		member.Reply(reply)
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
		member.Reply(reply)
	}
	channel.Quit(client)

	if !channel.flags[Persistent] && channel.IsEmpty() {
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
	if !(client.flags[Operator] || channel.members.Has(client)) {
		client.ErrNotOnChannel(channel)
		return
	}

	if channel.flags[OpOnlyTopic] && !channel.ClientIsOperator(client) {
		client.ErrChanOPrivIsNeeded(channel)
		return
	}

	channel.topic = topic
	channel.server.db.Exec(`
        UPDATE channel
          SET topic = ?
          WHERE name = ?`, channel.topic, channel.name)

	reply := RplTopicMsg(client, channel)
	for member := range channel.members {
		member.Reply(reply)
	}
}

func (channel *Channel) CanSpeak(client *Client) bool {
	if client.flags[Operator] {
		return true
	}
	if channel.flags[NoOutside] && !channel.members.Has(client) {
		return false
	}
	if channel.flags[Moderated] && !(channel.members.HasMode(client, Voice) ||
		channel.members.HasMode(client, ChannelOperator)) {
		return false
	}
	return true
}

func (channel *Channel) PrivMsg(client *Client, message string) {
	if !channel.CanSpeak(client) {
		client.ErrCannotSendToChan(channel)
		return
	}
	for member := range channel.members {
		if member == client {
			continue
		}
		member.Reply(RplPrivMsg(client, channel, message))
	}
}

func (channel *Channel) applyModeFlag(client *Client, mode ChannelMode,
	op ModeOp) bool {
	if !channel.ClientIsOperator(client) {
		client.ErrChanOPrivIsNeeded(channel)
		return false
	}

	switch op {
	case Add:
		channel.flags[mode] = true
		return true

	case Remove:
		delete(channel.flags, mode)
		return true
	}
	return false
}

func (channel *Channel) applyModeMember(client *Client, mode ChannelMode,
	op ModeOp, nick string) bool {
	if !channel.ClientIsOperator(client) {
		client.ErrChanOPrivIsNeeded(channel)
		return false
	}

	if nick == "" {
		client.ErrNeedMoreParams("MODE")
		return false
	}

	target := channel.server.clients.Get(nick)
	if target == nil {
		client.ErrNoSuchNick(nick)
		return false
	}

	if !channel.members.Has(target) {
		client.ErrUserNotInChannel(channel, target)
		return false
	}

	switch op {
	case Add:
		channel.members[target][mode] = true
		return true

	case Remove:
		channel.members[target][mode] = false
		return true
	}
	return false
}

func (channel *Channel) applyMode(client *Client, change *ChannelModeChange) bool {
	switch change.mode {
	case BanMask, ExceptMask, InviteMask:
		// TODO add/remove

		for _, mask := range channel.lists[change.mode] {
			client.RplMaskList(change.mode, channel, mask)
		}
		client.RplEndOfMaskList(change.mode, channel)

	case Moderated, NoOutside, OpOnlyTopic, Persistent, Private:
		return channel.applyModeFlag(client, change.mode, change.op)

	case Key:
		if !channel.ClientIsOperator(client) {
			client.ErrChanOPrivIsNeeded(channel)
			return false
		}

		switch change.op {
		case Add:
			if change.arg == "" {
				client.ErrNeedMoreParams("MODE")
				return false
			}

			channel.key = change.arg
			return true

		case Remove:
			channel.key = ""
			return true
		}

	case UserLimit:
		limit, err := strconv.ParseUint(change.arg, 10, 64)
		if err != nil {
			client.ErrNeedMoreParams("MODE")
			return false
		}
		if limit == 0 {
			return false
		}

		channel.userLimit = limit
		return true

	case ChannelOperator, Voice:
		return channel.applyModeMember(client, change.mode, change.op, change.arg)

	default:
		client.ErrUnknownMode(change.mode, channel)
		return false
	}
	return false
}

func (channel *Channel) Mode(client *Client, changes ChannelModeChanges) {
	if len(changes) == 0 {
		client.RplChannelModeIs(channel)
		return
	}

	applied := make(ChannelModeChanges, 0)
	for _, change := range changes {
		if channel.applyMode(client, change) {
			applied = append(applied, change)
		}
	}

	if len(applied) > 0 {
		reply := RplChannelMode(client, channel, applied)
		for member := range channel.members {
			member.Reply(reply)
		}

		channel.server.db.Exec(`
            UPDATE channel
              SET flags = ?
              WHERE name = ?`, channel.flags.String(), channel.name)
	}
}

func (channel *Channel) Notice(client *Client, message string) {
	if !channel.CanSpeak(client) {
		client.ErrCannotSendToChan(channel)
		return
	}
	for member := range channel.members {
		if member == client {
			continue
		}
		member.Reply(RplNotice(client, channel, message))
	}
}

func (channel *Channel) Quit(client *Client) {
	channel.members.Remove(client)
	client.channels.Remove(channel)
}

func (channel *Channel) Kick(client *Client, target *Client, comment string) {
	if !(client.flags[Operator] || channel.members.Has(client)) {
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

	reply := RplKick(channel, client, target, comment)
	for member := range channel.members {
		member.Reply(reply)
	}
	channel.Quit(target)
}

func (channel *Channel) Invite(invitee *Client, inviter *Client) {
	if channel.flags[InviteOnly] && !channel.ClientIsOperator(inviter) {
		inviter.ErrChanOPrivIsNeeded(channel)
		return
	}

	if !channel.members.Has(inviter) {
		inviter.ErrNotOnChannel(channel)
		return
	}

	// TODO Modify channel masks
	inviter.RplInviting(invitee, channel.name)
	invitee.Reply(RplInviteMsg(inviter, channel.name))
	if invitee.flags[Away] {
		inviter.RplAway(invitee)
	}
}
