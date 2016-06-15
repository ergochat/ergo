// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"log"
	"strconv"
)

type Channel struct {
	flags     ChannelModeSet
	lists     map[ChannelMode]*UserMaskSet
	key       Text
	members   MemberSet
	name      Name
	server    *Server
	topic     Text
	userLimit uint64
}

// NewChannel creates a new channel from a `Server` and a `name`
// string, which must be unique on the server.
func NewChannel(s *Server, name Name, addDefaultModes bool) *Channel {
	channel := &Channel{
		flags: make(ChannelModeSet),
		lists: map[ChannelMode]*UserMaskSet{
			BanMask:    NewUserMaskSet(),
			ExceptMask: NewUserMaskSet(),
			InviteMask: NewUserMaskSet(),
		},
		members: make(MemberSet),
		name:    name,
		server:  s,
	}

	if addDefaultModes {
		for _, mode := range DefaultChannelModes {
			channel.flags[mode] = true
		}
	}

	s.channels.Add(channel)

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

// Prefixes returns a list of prefixes for the given set of channel modes.
func (modes ChannelModeSet) Prefixes(isMultiPrefix bool) string {
	var prefixes string

	// add prefixes in order from highest to lowest privs
	for _, mode := range ChannelPrivModes {
		if modes[mode] {
			prefixes += ChannelModePrefixes[mode]
		}
	}
	if modes[Voice] {
		prefixes += ChannelModePrefixes[Voice]
	}

	if !isMultiPrefix && len(prefixes) > 1 {
		prefixes = string(prefixes[0])
	}

	return prefixes
}

func (channel *Channel) Nicks(target *Client) []string {
	isMultiPrefix := (target != nil) && target.capabilities[MultiPrefix]
	nicks := make([]string, len(channel.members))
	i := 0
	for client, modes := range channel.members {
		nicks[i] += modes.Prefixes(isMultiPrefix)
		nicks[i] += client.Nick().String()
		i += 1
	}
	return nicks
}

func (channel *Channel) Id() Name {
	return channel.name
}

func (channel *Channel) Nick() Name {
	return channel.name
}

func (channel *Channel) String() string {
	return channel.Id().String()
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

	str = "+" + str

	// args for flags with args: The order must match above to keep
	// positional arguments in place.
	if showKey {
		str += " " + channel.key.String()
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

func (channel *Channel) CheckKey(key Text) bool {
	return (channel.key == "") || (channel.key == key)
}

func (channel *Channel) Join(client *Client, key Text) {
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

	isInvited := channel.lists[InviteMask].Match(client.UserHost())
	if channel.flags[InviteOnly] && !isInvited {
		client.ErrInviteOnlyChan(channel)
		return
	}

	if channel.lists[BanMask].Match(client.UserHost()) &&
		!isInvited &&
		!channel.lists[ExceptMask].Match(client.UserHost()) {
		client.ErrBannedFromChan(channel)
		return
	}

	client.channels.Add(channel)
	channel.members.Add(client)
	if !channel.flags[Persistent] && (len(channel.members) == 1) {
		channel.members[client][ChannelFounder] = true
		channel.members[client][ChannelOperator] = true
	}

	reply := RplJoin(client, channel)
	for member := range channel.members {
		member.Reply(reply)
	}
	channel.GetTopic(client)
	channel.Names(client)
}

func (channel *Channel) Part(client *Client, message Text) {
	if !channel.members.Has(client) {
		client.ErrNotOnChannel(channel)
		return
	}

	reply := RplPart(client, channel, message)
	for member := range channel.members {
		member.Reply(reply)
	}
	channel.Quit(client)
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

func (channel *Channel) SetTopic(client *Client, topic Text) {
	if !(client.flags[Operator] || channel.members.Has(client)) {
		client.ErrNotOnChannel(channel)
		return
	}

	if channel.flags[OpOnlyTopic] && !channel.ClientIsOperator(client) {
		client.ErrChanOPrivIsNeeded(channel)
		return
	}

	channel.topic = topic

	reply := RplTopicMsg(client, channel)
	for member := range channel.members {
		member.Reply(reply)
	}

	if err := channel.Persist(); err != nil {
		log.Println("Channel.Persist:", channel, err)
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

func (channel *Channel) PrivMsg(client *Client, message Text) {
	if !channel.CanSpeak(client) {
		client.ErrCannotSendToChan(channel)
		return
	}
	reply := RplPrivMsg(client, channel, message)
	for member := range channel.members {
		if member == client {
			continue
		}
		member.Reply(reply)
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
		if channel.flags[mode] {
			return false
		}
		channel.flags[mode] = true
		return true

	case Remove:
		if !channel.flags[mode] {
			return false
		}
		delete(channel.flags, mode)
		return true
	}
	return false
}

func (channel *Channel) applyModeMember(client *Client, mode ChannelMode,
	op ModeOp, nick Name) bool {
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
		if channel.members[target][mode] {
			return false
		}
		channel.members[target][mode] = true
		return true

	case Remove:
		if !channel.members[target][mode] {
			return false
		}
		channel.members[target][mode] = false
		return true
	}
	return false
}

func (channel *Channel) ShowMaskList(client *Client, mode ChannelMode) {
	for lmask := range channel.lists[mode].masks {
		client.RplMaskList(mode, channel, lmask)
	}
	client.RplEndOfMaskList(mode, channel)
}

func (channel *Channel) applyModeMask(client *Client, mode ChannelMode, op ModeOp,
	mask Name) bool {
	list := channel.lists[mode]
	if list == nil {
		// This should never happen, but better safe than panicky.
		return false
	}

	if (op == List) || (mask == "") {
		channel.ShowMaskList(client, mode)
		return false
	}

	if !channel.ClientIsOperator(client) {
		client.ErrChanOPrivIsNeeded(channel)
		return false
	}

	if op == Add {
		return list.Add(mask)
	}

	if op == Remove {
		return list.Remove(mask)
	}

	return false
}

func (channel *Channel) applyMode(client *Client, change *ChannelModeChange) bool {
	switch change.mode {
	case BanMask, ExceptMask, InviteMask:
		return channel.applyModeMask(client, change.mode, change.op,
			NewName(change.arg))

	case InviteOnly, Moderated, NoOutside, OpOnlyTopic, Persistent, Secret:
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
			key := NewText(change.arg)
			if key == channel.key {
				return false
			}

			channel.key = key
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
		if (limit == 0) || (limit == channel.userLimit) {
			return false
		}

		channel.userLimit = limit
		return true

	case ChannelFounder, ChannelAdmin, ChannelOperator, Halfop, Voice:
		var hasPrivs bool

		// make sure client has privs to edit the given prefix
		for _, mode := range ChannelPrivModes {
			if channel.members[client][mode] {
				hasPrivs = true

				// Admins can't give other people Admin or remove it from others,
				// standard for that channel mode, we worry about this later
				if mode == ChannelAdmin && change.mode == ChannelAdmin {
					hasPrivs = false
				}

				break
			} else if mode == change.mode {
				break
			}
		}

		name := NewName(change.arg)

		if !hasPrivs {
			if change.op == Remove && name.ToLower() == client.nick.ToLower() {
				// success!
			} else {
				client.ErrChanOPrivIsNeeded(channel)
				return false
			}
		}

		return channel.applyModeMember(client, change.mode, change.op, name)

	default:
		client.ErrUnknownMode(change.mode, channel)
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

		if err := channel.Persist(); err != nil {
			log.Println("Channel.Persist:", channel, err)
		}
	}
}

func (channel *Channel) Persist() (err error) {
	if channel.flags[Persistent] {
		_, err = channel.server.db.Exec(`
            INSERT OR REPLACE INTO channel
              (name, flags, key, topic, user_limit, ban_list, except_list,
               invite_list)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			channel.name.String(), channel.flags.String(), channel.key.String(),
			channel.topic.String(), channel.userLimit, channel.lists[BanMask].String(),
			channel.lists[ExceptMask].String(), channel.lists[InviteMask].String())
	} else {
		_, err = channel.server.db.Exec(`
            DELETE FROM channel WHERE name = ?`, channel.name.String())
	}
	return
}

func (channel *Channel) Notice(client *Client, message Text) {
	if !channel.CanSpeak(client) {
		client.ErrCannotSendToChan(channel)
		return
	}
	reply := RplNotice(client, channel, message)
	for member := range channel.members {
		if member == client {
			continue
		}
		member.Reply(reply)
	}
}

func (channel *Channel) Quit(client *Client) {
	channel.members.Remove(client)
	client.channels.Remove(channel)

	if !channel.flags[Persistent] && channel.IsEmpty() {
		channel.server.channels.Remove(channel)
	}
}

func (channel *Channel) Kick(client *Client, target *Client, comment Text) {
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

	if channel.flags[InviteOnly] {
		channel.lists[InviteMask].Add(invitee.UserHost())
		if err := channel.Persist(); err != nil {
			log.Println("Channel.Persist:", channel, err)
		}
	}

	inviter.RplInviting(invitee, channel.name)
	invitee.Reply(RplInviteMsg(inviter, invitee, channel.name))
	if invitee.flags[Away] {
		inviter.RplAway(invitee)
	}
}
