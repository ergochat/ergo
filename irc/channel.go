// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"log"
	"strconv"
	"time"
)

type Channel struct {
	flags        ChannelModeSet
	lists        map[ChannelMode]*UserMaskSet
	key          string
	members      MemberSet
	name         Name
	nameString   string
	server       *Server
	createdTime  time.Time
	topic        string
	topicSetBy   string
	topicSetTime time.Time
	userLimit    uint64
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
		members:    make(MemberSet),
		name:       name,
		nameString: name.String(),
		server:     s,
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
	currentNicks := channel.Nicks(client)
	// assemble and send replies
	maxNamLen := 480 - len(client.server.nameString) - len(client.nickString)
	var buffer string
	for _, nick := range currentNicks {
		if buffer == "" {
			buffer += nick
			continue
		}

		if len(buffer)+1+len(nick) > maxNamLen {
			client.Send(nil, client.server.nameString, RPL_NAMREPLY, client.nickString, "=", channel.nameString, buffer)
			buffer = nick
			continue
		}

		buffer += " "
		buffer += nick
	}

	client.Send(nil, client.server.nameString, RPL_NAMREPLY, client.nickString, "=", channel.nameString, buffer)
	client.Send(nil, client.server.nameString, RPL_ENDOFNAMES, client.nickString, channel.nameString, "End of NAMES list")
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
	isUserhostInNames := (target != nil) && target.capabilities[UserhostInNames]
	nicks := make([]string, len(channel.members))
	i := 0
	for client, modes := range channel.members {
		nicks[i] += modes.Prefixes(isMultiPrefix)
		if isUserhostInNames {
			nicks[i] += client.nickMaskString
		} else {
			nicks[i] += client.nickString
		}
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
		str += " " + channel.key
	}
	if showUserLimit {
		str += " " + strconv.FormatUint(channel.userLimit, 10)
	}

	return str
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
		client.Send(nil, client.server.nameString, ERR_CHANNELISFULL, channel.nameString, "Cannot join channel (+l)")
		return
	}

	if !channel.CheckKey(key) {
		client.Send(nil, client.server.nameString, ERR_BADCHANNELKEY, channel.nameString, "Cannot join channel (+k)")
		return
	}

	isInvited := channel.lists[InviteMask].Match(client.UserHost())
	if channel.flags[InviteOnly] && !isInvited {
		client.Send(nil, client.server.nameString, ERR_INVITEONLYCHAN, channel.nameString, "Cannot join channel (+i)")
		return
	}

	if channel.lists[BanMask].Match(client.UserHost()) &&
		!isInvited &&
		!channel.lists[ExceptMask].Match(client.UserHost()) {
		client.Send(nil, client.server.nameString, ERR_BANNEDFROMCHAN, channel.nameString, "Cannot join channel (+b)")
		return
	}

	for member := range channel.members {
		if member.capabilities[ExtendedJoin] {
			member.Send(nil, client.nickMaskString, "JOIN", channel.nameString, client.accountName, client.realname)
		} else {
			member.Send(nil, client.nickMaskString, "JOIN", channel.nameString)
		}
	}

	client.channels.Add(channel)
	channel.members.Add(client)
	if !channel.flags[Persistent] && (len(channel.members) == 1) {
		channel.createdTime = time.Now()
		channel.members[client][ChannelFounder] = true
		channel.members[client][ChannelOperator] = true
	}

	if client.capabilities[ExtendedJoin] {
		client.Send(nil, client.nickMaskString, "JOIN", channel.nameString, client.accountName, client.realname)
	} else {
		client.Send(nil, client.nickMaskString, "JOIN", channel.nameString)
	}
	channel.GetTopic(client)
	channel.Names(client)
}

func (channel *Channel) Part(client *Client, message string) {
	if !channel.members.Has(client) {
		client.Send(nil, client.server.nameString, ERR_NOTONCHANNEL, channel.nameString, "You're not on that channel")
		return
	}

	for member := range channel.members {
		member.Send(nil, client.nickMaskString, "PART", channel.nameString, message)
	}
	channel.Quit(client)
}

func (channel *Channel) GetTopic(client *Client) {
	if !channel.members.Has(client) {
		client.Send(nil, client.server.nameString, ERR_NOTONCHANNEL, client.nickString, channel.nameString, "You're not on that channel")
		return
	}

	if channel.topic == "" {
		client.Send(nil, client.server.nameString, RPL_NOTOPIC, client.nickString, channel.nameString, "No topic is set")
		return
	}

	client.Send(nil, client.server.nameString, RPL_TOPIC, client.nickString, channel.nameString, channel.topic)
	client.Send(nil, client.server.nameString, RPL_TOPICTIME, client.nickString, channel.nameString, channel.topicSetBy, strconv.FormatInt(channel.topicSetTime.Unix(), 10))
}

func (channel *Channel) SetTopic(client *Client, topic string) {
	if !(client.flags[Operator] || channel.members.Has(client)) {
		client.Send(nil, client.server.nameString, ERR_NOTONCHANNEL, channel.nameString, "You're not on that channel")
		return
	}

	if channel.flags[OpOnlyTopic] && !channel.ClientIsOperator(client) {
		client.Send(nil, client.server.nameString, ERR_CHANOPRIVSNEEDED, channel.nameString, "You're not a channel operator")
		return
	}

	channel.topic = topic
	channel.topicSetBy = client.nickString
	channel.topicSetTime = time.Now()

	for member := range channel.members {
		member.Send(nil, client.nickMaskString, "TOPIC", channel.nameString, channel.topic)
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

func (channel *Channel) PrivMsg(client *Client, message string) {
	if !channel.CanSpeak(client) {
		client.Send(nil, client.server.nameString, ERR_CANNOTSENDTOCHAN, channel.nameString, "Cannot send to channel")
		return
	}
	for member := range channel.members {
		if member == client {
			continue
		}
		//TODO(dan): use nickmask instead of nickString here lel
		member.Send(nil, client.nickMaskString, "PRIVMSG", channel.nameString, message)
	}
}

func (channel *Channel) applyModeFlag(client *Client, mode ChannelMode,
	op ModeOp) bool {
	if !channel.ClientIsOperator(client) {
		client.Send(nil, client.server.nameString, ERR_CHANOPRIVSNEEDED, channel.nameString, "You're not a channel operator")
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
	op ModeOp, nick string) *ChannelModeChange {
	if nick == "" {
		//TODO(dan): shouldn't this be handled before it reaches this function?
		client.Send(nil, client.server.nameString, ERR_NEEDMOREPARAMS, "MODE", "Not enough parameters")
		return nil
	}

	target := channel.server.clients.Get(Name(nick))
	if target == nil {
		//TODO(dan): investigate using NOSUCHNICK and NOSUCHCHANNEL specifically as that other IRCd (insp?) does,
		// since I think that would make sense
		client.Send(nil, client.server.nameString, ERR_NOSUCHNICK, nick, "No such nick")
		return nil
	}

	if !channel.members.Has(target) {
		client.Send(nil, client.server.nameString, ERR_USERNOTINCHANNEL, client.nickString, channel.nameString, "They aren't on that channel")
		return nil
	}

	switch op {
	case Add:
		if channel.members[target][mode] {
			return nil
		}
		channel.members[target][mode] = true
		return &ChannelModeChange{
			op:   Add,
			mode: mode,
			arg:  nick,
		}

	case Remove:
		if !channel.members[target][mode] {
			return nil
		}
		channel.members[target][mode] = false
		return &ChannelModeChange{
			op:   Remove,
			mode: mode,
			arg:  nick,
		}
	}
	return nil
}

func (channel *Channel) ShowMaskList(client *Client, mode ChannelMode) {
	//TODO(dan): WE NEED TO fiX this PROPERLY
	log.Fatal("Implement ShowMaskList")
	/*
		for lmask := range channel.lists[mode].masks {
			client.RplMaskList(mode, channel, lmask)
		}
		client.RplEndOfMaskList(mode, channel)*/
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
		client.Send(nil, client.server.nameString, ERR_CHANOPRIVSNEEDED, channel.nameString, "You're not a channel operator")
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

func (channel *Channel) Persist() (err error) {
	if channel.flags[Persistent] {
		//TODO(dan): Save topicSetBy/topicSetTime and createdTime
		_, err = channel.server.db.Exec(`
            INSERT OR REPLACE INTO channel
              (name, flags, key, topic, user_limit, ban_list, except_list,
               invite_list)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			channel.name.String(), channel.flags.String(), channel.key,
			channel.topic, channel.userLimit, channel.lists[BanMask].String(),
			channel.lists[ExceptMask].String(), channel.lists[InviteMask].String())
	} else {
		_, err = channel.server.db.Exec(`
            DELETE FROM channel WHERE name = ?`, channel.name.String())
	}
	return
}

func (channel *Channel) Notice(client *Client, message string) {
	if !channel.CanSpeak(client) {
		client.Send(nil, client.server.nameString, ERR_CANNOTSENDTOCHAN, channel.nameString, "Cannot send to channel")
		return
	}
	for member := range channel.members {
		if member == client {
			continue
		}
		member.Send(nil, client.nickMaskString, "NOTICE", channel.nameString, message)
	}
}

func (channel *Channel) Quit(client *Client) {
	channel.members.Remove(client)
	client.channels.Remove(channel)

	if !channel.flags[Persistent] && channel.IsEmpty() {
		channel.server.channels.Remove(channel)
	}
}

func (channel *Channel) Kick(client *Client, target *Client, comment string) {
	if !(client.flags[Operator] || channel.members.Has(client)) {
		client.Send(nil, client.server.nameString, ERR_NOTONCHANNEL, channel.nameString, "You're not on that channel")
		return
	}
	if !channel.ClientIsOperator(client) {
		client.Send(nil, client.server.nameString, ERR_CANNOTSENDTOCHAN, channel.nameString, "Cannot send to channel")
		return
	}
	if !channel.members.Has(target) {
		client.Send(nil, client.server.nameString, ERR_USERNOTINCHANNEL, client.nickString, channel.nameString, "They aren't on that channel")
		return
	}

	for member := range channel.members {
		member.Send(nil, client.nickMaskString, "KICK", channel.nameString, target.nickString, comment)
	}
	channel.Quit(target)
}

func (channel *Channel) Invite(invitee *Client, inviter *Client) {
	if channel.flags[InviteOnly] && !channel.ClientIsOperator(inviter) {
		inviter.Send(nil, inviter.server.nameString, ERR_CHANOPRIVSNEEDED, channel.nameString, "You're not a channel operator")
		return
	}

	if !channel.members.Has(inviter) {
		inviter.Send(nil, inviter.server.nameString, ERR_NOTONCHANNEL, channel.nameString, "You're not on that channel")
		return
	}

	if channel.flags[InviteOnly] {
		channel.lists[InviteMask].Add(invitee.UserHost())
		if err := channel.Persist(); err != nil {
			log.Println("Channel.Persist:", channel, err)
		}
	}

	//TODO(dan): should inviter.server.nameString here be inviter.nickMaskString ?
	inviter.Send(nil, inviter.server.nameString, RPL_INVITING, invitee.nickString, channel.nameString)
	invitee.Send(nil, inviter.nickMaskString, "INVITE", invitee.nickString, channel.nameString)
	if invitee.flags[Away] {
		inviter.Send(nil, inviter.server.nameString, RPL_AWAY, invitee.nickString, invitee.awayMessage)
	}
}
