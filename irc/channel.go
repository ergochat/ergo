// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/DanielOaks/girc-go/ircmsg"
)

type Channel struct {
	flags          ChannelModeSet
	lists          map[ChannelMode]*UserMaskSet
	key            string
	members        MemberSet
	name           string
	nameCasefolded string
	server         *Server
	createdTime    time.Time
	topic          string
	topicSetBy     string
	topicSetTime   time.Time
	userLimit      uint64
}

// NewChannel creates a new channel from a `Server` and a `name`
// string, which must be unique on the server.
func NewChannel(s *Server, name string, addDefaultModes bool) *Channel {
	casefoldedName, err := CasefoldChannel(name)
	if err != nil {
		log.Println(fmt.Sprintf("ERROR: Channel name is bad: [%s]", name), err.Error())
		return nil
	}

	channel := &Channel{
		flags: make(ChannelModeSet),
		lists: map[ChannelMode]*UserMaskSet{
			BanMask:    NewUserMaskSet(),
			ExceptMask: NewUserMaskSet(),
			InviteMask: NewUserMaskSet(),
		},
		members:        make(MemberSet),
		name:           name,
		nameCasefolded: casefoldedName,
		server:         s,
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
	maxNamLen := 480 - len(client.server.name) - len(client.nick)
	var buffer string
	for _, nick := range currentNicks {
		if buffer == "" {
			buffer += nick
			continue
		}

		if len(buffer)+1+len(nick) > maxNamLen {
			client.Send(nil, client.server.name, RPL_NAMREPLY, client.nick, "=", channel.name, buffer)
			buffer = nick
			continue
		}

		buffer += " "
		buffer += nick
	}

	client.Send(nil, client.server.name, RPL_NAMREPLY, client.nick, "=", channel.name, buffer)
	client.Send(nil, client.server.name, RPL_ENDOFNAMES, client.nick, channel.name, "End of NAMES list")
}

// ClientIsHalfOp returns whether client is at least a halfop.
func (channel *Channel) ClientIsHalfOp(client *Client) bool {
	return client.flags[Operator] || channel.members.HasMode(client, Halfop) || channel.members.HasMode(client, ChannelOperator) || channel.members.HasMode(client, ChannelAdmin) || channel.members.HasMode(client, ChannelFounder)
}

// ClientIsOperator returns whether client is at least a chanop.
func (channel *Channel) ClientIsOperator(client *Client) bool {
	return client.flags[Operator] || channel.members.HasMode(client, ChannelOperator) || channel.members.HasMode(client, ChannelAdmin) || channel.members.HasMode(client, ChannelFounder)
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
			nicks[i] += client.nick
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
		client.Send(nil, client.server.name, ERR_CHANNELISFULL, channel.name, "Cannot join channel (+l)")
		return
	}

	if !channel.CheckKey(key) {
		client.Send(nil, client.server.name, ERR_BADCHANNELKEY, channel.name, "Cannot join channel (+k)")
		return
	}

	isInvited := channel.lists[InviteMask].Match(client.UserHost())
	if channel.flags[InviteOnly] && !isInvited {
		client.Send(nil, client.server.name, ERR_INVITEONLYCHAN, channel.name, "Cannot join channel (+i)")
		return
	}

	if channel.lists[BanMask].Match(client.UserHost()) &&
		!isInvited &&
		!channel.lists[ExceptMask].Match(client.UserHost()) {
		client.Send(nil, client.server.name, ERR_BANNEDFROMCHAN, channel.name, "Cannot join channel (+b)")
		return
	}

	for member := range channel.members {
		if member.capabilities[ExtendedJoin] {
			member.Send(nil, client.nickMaskString, "JOIN", channel.name, client.account.Name, client.realname)
		} else {
			member.Send(nil, client.nickMaskString, "JOIN", channel.name)
		}
	}

	client.channels.Add(channel)
	channel.members.Add(client)
	if len(channel.members) == 1 {
		channel.createdTime = time.Now()
		channel.members[client][ChannelFounder] = true
		channel.members[client][ChannelOperator] = true
	}

	if client.capabilities[ExtendedJoin] {
		client.Send(nil, client.nickMaskString, "JOIN", channel.name, client.account.Name, client.realname)
	} else {
		client.Send(nil, client.nickMaskString, "JOIN", channel.name)
	}
	channel.GetTopic(client)
	channel.Names(client)
}

func (channel *Channel) Part(client *Client, message string) {
	if !channel.members.Has(client) {
		client.Send(nil, client.server.name, ERR_NOTONCHANNEL, channel.name, "You're not on that channel")
		return
	}

	for member := range channel.members {
		member.Send(nil, client.nickMaskString, "PART", channel.name, message)
	}
	channel.Quit(client)
}

func (channel *Channel) GetTopic(client *Client) {
	if !channel.members.Has(client) {
		client.Send(nil, client.server.name, ERR_NOTONCHANNEL, client.nick, channel.name, "You're not on that channel")
		return
	}

	if channel.topic == "" {
		client.Send(nil, client.server.name, RPL_NOTOPIC, client.nick, channel.name, "No topic is set")
		return
	}

	client.Send(nil, client.server.name, RPL_TOPIC, client.nick, channel.name, channel.topic)
	client.Send(nil, client.server.name, RPL_TOPICTIME, client.nick, channel.name, channel.topicSetBy, strconv.FormatInt(channel.topicSetTime.Unix(), 10))
}

func (channel *Channel) SetTopic(client *Client, topic string) {
	if !(client.flags[Operator] || channel.members.Has(client)) {
		client.Send(nil, client.server.name, ERR_NOTONCHANNEL, channel.name, "You're not on that channel")
		return
	}

	if channel.flags[OpOnlyTopic] && !channel.ClientIsOperator(client) {
		client.Send(nil, client.server.name, ERR_CHANOPRIVSNEEDED, channel.name, "You're not a channel operator")
		return
	}

	if len(topic) > client.server.limits.TopicLen {
		topic = topic[:client.server.limits.TopicLen]
	}

	channel.topic = topic
	channel.topicSetBy = client.nick
	channel.topicSetTime = time.Now()

	for member := range channel.members {
		member.Send(nil, client.nickMaskString, "TOPIC", channel.name, channel.topic)
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

func (channel *Channel) PrivMsg(clientOnlyTags *map[string]ircmsg.TagValue, client *Client, message string) {
	if !channel.CanSpeak(client) {
		client.Send(nil, client.server.name, ERR_CANNOTSENDTOCHAN, channel.name, "Cannot send to channel")
		return
	}
	for member := range channel.members {
		if member == client && !client.capabilities[EchoMessage] {
			continue
		}
		if member.capabilities[MessageTags] {
			member.SendFromClient(client, clientOnlyTags, client.nickMaskString, "PRIVMSG", channel.name, message)
		} else {
			member.SendFromClient(client, nil, client.nickMaskString, "PRIVMSG", channel.name, message)
		}
	}
}

func (channel *Channel) applyModeFlag(client *Client, mode ChannelMode,
	op ModeOp) bool {
	if !channel.ClientIsOperator(client) {
		client.Send(nil, client.server.name, ERR_CHANOPRIVSNEEDED, channel.name, "You're not a channel operator")
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
		client.Send(nil, client.server.name, ERR_NEEDMOREPARAMS, "MODE", "Not enough parameters")
		return nil
	}

	casefoldedName, err := CasefoldName(nick)
	target := channel.server.clients.Get(casefoldedName)
	if err != nil || target == nil {
		client.Send(nil, client.server.name, ERR_NOSUCHNICK, nick, "No such nick")
		return nil
	}

	if !channel.members.Has(target) {
		client.Send(nil, client.server.name, ERR_USERNOTINCHANNEL, client.nick, channel.name, "They aren't on that channel")
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

func (channel *Channel) applyModeMask(client *Client, mode ChannelMode, op ModeOp, mask string) bool {
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
		client.Send(nil, client.server.name, ERR_CHANOPRIVSNEEDED, channel.name, "You're not a channel operator")
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

func (channel *Channel) Notice(client *Client, message string) {
	if !channel.CanSpeak(client) {
		client.Send(nil, client.server.name, ERR_CANNOTSENDTOCHAN, channel.name, "Cannot send to channel")
		return
	}
	for member := range channel.members {
		if member == client {
			continue
		}
		member.SendFromClient(client, nil, client.nickMaskString, "NOTICE", channel.name, message)
	}
}

func (channel *Channel) Quit(client *Client) {
	channel.members.Remove(client)
	client.channels.Remove(channel)

	if channel.IsEmpty() {
		channel.server.channels.Remove(channel)
	}
}

func (channel *Channel) Kick(client *Client, target *Client, comment string) {
	if !(client.flags[Operator] || channel.members.Has(client)) {
		client.Send(nil, client.server.name, ERR_NOTONCHANNEL, channel.name, "You're not on that channel")
		return
	}
	if !channel.ClientIsOperator(client) {
		client.Send(nil, client.server.name, ERR_CANNOTSENDTOCHAN, channel.name, "Cannot send to channel")
		return
	}
	if !channel.members.Has(target) {
		client.Send(nil, client.server.name, ERR_USERNOTINCHANNEL, client.nick, channel.name, "They aren't on that channel")
		return
	}

	if len(comment) > client.server.limits.KickLen {
		comment = comment[:client.server.limits.KickLen]
	}

	for member := range channel.members {
		member.Send(nil, client.nickMaskString, "KICK", channel.name, target.nick, comment)
	}
	channel.Quit(target)
}

func (channel *Channel) Invite(invitee *Client, inviter *Client) {
	if channel.flags[InviteOnly] && !channel.ClientIsOperator(inviter) {
		inviter.Send(nil, inviter.server.name, ERR_CHANOPRIVSNEEDED, channel.name, "You're not a channel operator")
		return
	}

	if !channel.members.Has(inviter) {
		inviter.Send(nil, inviter.server.name, ERR_NOTONCHANNEL, channel.name, "You're not on that channel")
		return
	}

	//TODO(dan): handle this more nicely, keep a list of last X invited channels on invitee rather than explicitly modifying the invite list?
	if channel.flags[InviteOnly] {
		channel.lists[InviteMask].Add(invitee.UserHost())
	}

	// send invite-notify
	for member := range channel.members {
		if member.capabilities[InviteNotify] && member != inviter && member != invitee && channel.ClientIsHalfOp(member) {
			member.Send(nil, inviter.nickMaskString, "INVITE", invitee.nick, channel.name)
		}
	}

	//TODO(dan): should inviter.server.name here be inviter.nickMaskString ?
	inviter.Send(nil, inviter.server.name, RPL_INVITING, invitee.nick, channel.name)
	invitee.Send(nil, inviter.nickMaskString, "INVITE", invitee.nick, channel.name)
	if invitee.flags[Away] {
		inviter.Send(nil, inviter.server.name, RPL_AWAY, invitee.nick, invitee.awayMessage)
	}
}
