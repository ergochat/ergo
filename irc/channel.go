// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"sync"

	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/tidwall/buntdb"
)

// Channel represents a channel that clients can join.
type Channel struct {
	flags          ModeSet
	lists          map[Mode]*UserMaskSet
	key            string
	membersMutex   sync.RWMutex
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
		flags: make(ModeSet),
		lists: map[Mode]*UserMaskSet{
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
		for _, mode := range s.defaultChannelModes {
			channel.flags[mode] = true
		}
	}

	s.channels.Add(channel)

	return channel
}

// IsEmpty returns true if the channel has no clients.
func (channel *Channel) IsEmpty() bool {
	channel.membersMutex.RLock()
	defer channel.membersMutex.RUnlock()

	return channel.isEmptyNoMutex()
}

func (channel *Channel) isEmptyNoMutex() bool {
	return len(channel.members) == 0
}

// Names sends the list of users joined to the channel to the given client.
func (channel *Channel) Names(client *Client) {
	channel.membersMutex.RLock()
	defer channel.membersMutex.RUnlock()

	channel.namesNoMutex(client)
}

func (channel *Channel) namesNoMutex(client *Client) {
	currentNicks := channel.nicksNoMutex(client)
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

// ClientIsAtLeast returns whether the client has at least the given channel privilege.
func (channel *Channel) ClientIsAtLeast(client *Client, permission Mode) bool {
	channel.membersMutex.RLock()
	defer channel.membersMutex.RUnlock()

	return channel.clientIsAtLeastNoMutex(client, permission)
}

func (channel *Channel) clientIsAtLeastNoMutex(client *Client, permission Mode) bool {
	// requires RLock()

	// get voice, since it's not a part of ChannelPrivModes
	if channel.members.HasMode(client, permission) {
		return true
	}

	// check regular modes
	for _, mode := range ChannelPrivModes {
		if channel.members.HasMode(client, mode) {
			return true
		}

		if mode == permission {
			break
		}
	}

	return false
}

// Prefixes returns a list of prefixes for the given set of channel modes.
func (modes ModeSet) Prefixes(isMultiPrefix bool) string {
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

func (channel *Channel) nicksNoMutex(target *Client) []string {
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
		i++
	}
	return nicks
}

// <mode> <mode params>
func (channel *Channel) modeStringNoLock(client *Client) (str string) {
	// RLock()
	isMember := client.flags[Operator] || channel.members.Has(client)
	// RUnlock()
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

// IsFull returns true if this channel is at its' members limit.
func (channel *Channel) IsFull() bool {
	return (channel.userLimit > 0) && (uint64(len(channel.members)) >= channel.userLimit)
}

// CheckKey returns true if the key is not set or matches the given key.
func (channel *Channel) CheckKey(key string) bool {
	return (channel.key == "") || (channel.key == key)
}

// Join joins the given client to this channel (if they can be joined).
//TODO(dan): /SAJOIN and maybe a ForceJoin function?
func (channel *Channel) Join(client *Client, key string) {
	channel.membersMutex.Lock()
	defer channel.membersMutex.Unlock()
	if channel.members.Has(client) {
		// already joined, no message needs to be sent
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

	isInvited := channel.lists[InviteMask].Match(client.nickMaskCasefolded)
	if channel.flags[InviteOnly] && !isInvited {
		client.Send(nil, client.server.name, ERR_INVITEONLYCHAN, channel.name, "Cannot join channel (+i)")
		return
	}

	if channel.lists[BanMask].Match(client.nickMaskCasefolded) &&
		!isInvited &&
		!channel.lists[ExceptMask].Match(client.nickMaskCasefolded) {
		client.Send(nil, client.server.name, ERR_BANNEDFROMCHAN, channel.name, "Cannot join channel (+b)")
		return
	}

	client.server.logger.Debug("join", fmt.Sprintf("%s joined channel %s", client.nick, channel.name))

	for member := range channel.members {
		if member.capabilities[ExtendedJoin] {
			member.Send(nil, client.nickMaskString, "JOIN", channel.name, client.account.Name, client.realname)
		} else {
			member.Send(nil, client.nickMaskString, "JOIN", channel.name)
		}
	}

	client.channels.Add(channel)
	channel.members.Add(client)

	// give channel mode if necessary
	var givenMode *Mode
	client.server.registeredChannelsMutex.Lock()
	defer client.server.registeredChannelsMutex.Unlock()
	client.server.store.Update(func(tx *buntdb.Tx) error {
		chanReg := client.server.loadChannelNoMutex(tx, channel.nameCasefolded)

		if chanReg == nil {
			if len(channel.members) == 1 {
				channel.createdTime = time.Now()
				channel.members[client][ChannelOperator] = true
				givenMode = &ChannelOperator
			}
		} else {
			// we should only do this on registered channels
			if client.account != nil && client.account.Name == chanReg.Founder {
				channel.members[client][ChannelFounder] = true
				givenMode = &ChannelFounder
			}
			if len(channel.members) == 1 {
				// apply other details if new channel
				channel.topic = chanReg.Topic
				channel.topicSetBy = chanReg.TopicSetBy
				channel.topicSetTime = chanReg.TopicSetTime
				channel.name = chanReg.Name
				channel.createdTime = chanReg.RegisteredAt
				for _, mask := range chanReg.Banlist {
					channel.lists[BanMask].Add(mask)
				}
				for _, mask := range chanReg.Exceptlist {
					channel.lists[ExceptMask].Add(mask)
				}
				for _, mask := range chanReg.Invitelist {
					channel.lists[InviteMask].Add(mask)
				}
			}
		}
		return nil
	})

	if client.capabilities[ExtendedJoin] {
		client.Send(nil, client.nickMaskString, "JOIN", channel.name, client.account.Name, client.realname)
	} else {
		client.Send(nil, client.nickMaskString, "JOIN", channel.name)
	}
	channel.getTopicNoMutex(client) // we already have Lock
	channel.namesNoMutex(client)
	if givenMode != nil {
		for member := range channel.members {
			member.Send(nil, client.server.name, "MODE", channel.name, fmt.Sprintf("+%v", *givenMode), client.nick)
		}
	}
}

// Part parts the given client from this channel, with the given message.
func (channel *Channel) Part(client *Client, message string) {
	channel.membersMutex.Lock()
	defer channel.membersMutex.Unlock()

	if !channel.members.Has(client) {
		client.Send(nil, client.server.name, ERR_NOTONCHANNEL, channel.name, "You're not on that channel")
		return
	}

	for member := range channel.members {
		member.Send(nil, client.nickMaskString, "PART", channel.name, message)
	}
	channel.quitNoMutex(client)

	client.server.logger.Debug("part", fmt.Sprintf("%s left channel %s", client.nick, channel.name))
}

// GetTopic sends the channel topic to the given client.
func (channel *Channel) GetTopic(client *Client) {
	channel.membersMutex.RLock()
	defer channel.membersMutex.RUnlock()

	channel.getTopicNoMutex(client)
}

// GetTopic sends the channel topic to the given client without getting the membersMutex.
// This is required because of channel joins.
func (channel *Channel) getTopicNoMutex(client *Client) {
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

// SetTopic sets the topic of this channel, if the client is allowed to do so.
func (channel *Channel) SetTopic(client *Client, topic string) {
	channel.membersMutex.RLock()
	defer channel.membersMutex.RUnlock()

	if !(client.flags[Operator] || channel.members.Has(client)) {
		client.Send(nil, client.server.name, ERR_NOTONCHANNEL, channel.name, "You're not on that channel")
		return
	}

	if channel.flags[OpOnlyTopic] && !channel.ClientIsAtLeast(client, ChannelOperator) {
		client.Send(nil, client.server.name, ERR_CHANOPRIVSNEEDED, channel.name, "You're not a channel operator")
		return
	}

	if len(topic) > client.server.limits.TopicLen {
		topic = topic[:client.server.limits.TopicLen]
	}

	channel.topic = topic
	channel.topicSetBy = client.nickMaskString
	channel.topicSetTime = time.Now()

	for member := range channel.members {
		member.Send(nil, client.nickMaskString, "TOPIC", channel.name, channel.topic)
	}

	// update saved channel topic for registered chans
	client.server.registeredChannelsMutex.Lock()
	defer client.server.registeredChannelsMutex.Unlock()

	client.server.store.Update(func(tx *buntdb.Tx) error {
		chanInfo := client.server.loadChannelNoMutex(tx, channel.nameCasefolded)

		if chanInfo == nil {
			return nil
		}

		chanInfo.Topic = topic
		chanInfo.TopicSetBy = client.nickMaskString
		chanInfo.TopicSetTime = time.Now()
		client.server.saveChannelNoMutex(tx, channel.nameCasefolded, *chanInfo)
		return nil
	})
}

// CanSpeak returns true if the client can speak on this channel.
func (channel *Channel) CanSpeak(client *Client) bool {
	channel.membersMutex.RLock()
	defer channel.membersMutex.RUnlock()

	if client.flags[Operator] {
		return true
	}
	if channel.flags[NoOutside] && !channel.members.Has(client) {
		return false
	}
	if channel.flags[Moderated] && !channel.clientIsAtLeastNoMutex(client, Voice) {
		return false
	}
	if channel.flags[RegisteredOnly] && client.account == &NoAccount {
		return false
	}
	return true
}

// TagMsg sends a tag message to everyone in this channel who can accept them.
func (channel *Channel) TagMsg(msgid string, minPrefix *Mode, clientOnlyTags *map[string]ircmsg.TagValue, client *Client) {
	channel.sendMessage(msgid, "TAGMSG", []Capability{MessageTags}, minPrefix, clientOnlyTags, client, nil)
}

// sendMessage sends a given message to everyone on this channel.
func (channel *Channel) sendMessage(msgid, cmd string, requiredCaps []Capability, minPrefix *Mode, clientOnlyTags *map[string]ircmsg.TagValue, client *Client, message *string) {
	if !channel.CanSpeak(client) {
		client.Send(nil, client.server.name, ERR_CANNOTSENDTOCHAN, channel.name, "Cannot send to channel")
		return
	}

	channel.membersMutex.RLock()
	defer channel.membersMutex.RUnlock()

	// for STATUSMSG
	var minPrefixMode Mode
	if minPrefix != nil {
		minPrefixMode = *minPrefix
	}
	for member := range channel.members {
		if minPrefix != nil && !channel.ClientIsAtLeast(member, minPrefixMode) {
			// STATUSMSG
			continue
		}
		if member == client && !client.capabilities[EchoMessage] {
			continue
		}

		canReceive := true
		for _, capName := range requiredCaps {
			if !member.capabilities[capName] {
				canReceive = false
			}
		}
		if !canReceive {
			continue
		}

		var messageTagsToUse *map[string]ircmsg.TagValue
		if member.capabilities[MessageTags] {
			messageTagsToUse = clientOnlyTags
		}

		if message == nil {
			member.SendFromClient(msgid, client, messageTagsToUse, cmd, channel.name)
		} else {
			member.SendFromClient(msgid, client, messageTagsToUse, cmd, channel.name, *message)
		}
	}
}

// SplitPrivMsg sends a private message to everyone in this channel.
func (channel *Channel) SplitPrivMsg(msgid string, minPrefix *Mode, clientOnlyTags *map[string]ircmsg.TagValue, client *Client, message SplitMessage) {
	channel.sendSplitMessage(msgid, "PRIVMSG", minPrefix, clientOnlyTags, client, &message)
}

// SplitNotice sends a private message to everyone in this channel.
func (channel *Channel) SplitNotice(msgid string, minPrefix *Mode, clientOnlyTags *map[string]ircmsg.TagValue, client *Client, message SplitMessage) {
	channel.sendSplitMessage(msgid, "NOTICE", minPrefix, clientOnlyTags, client, &message)
}

func (channel *Channel) sendSplitMessage(msgid, cmd string, minPrefix *Mode, clientOnlyTags *map[string]ircmsg.TagValue, client *Client, message *SplitMessage) {
	if !channel.CanSpeak(client) {
		client.Send(nil, client.server.name, ERR_CANNOTSENDTOCHAN, channel.name, "Cannot send to channel")
		return
	}

	channel.membersMutex.RLock()
	defer channel.membersMutex.RUnlock()

	// for STATUSMSG
	var minPrefixMode Mode
	if minPrefix != nil {
		minPrefixMode = *minPrefix
	}
	for member := range channel.members {
		if minPrefix != nil && !channel.ClientIsAtLeast(member, minPrefixMode) {
			// STATUSMSG
			continue
		}
		if member == client && !client.capabilities[EchoMessage] {
			continue
		}
		var tagsToUse *map[string]ircmsg.TagValue
		if member.capabilities[MessageTags] {
			tagsToUse = clientOnlyTags
		}

		if message == nil {
			member.SendFromClient(msgid, client, tagsToUse, cmd, channel.name)
		} else {
			member.SendSplitMsgFromClient(msgid, client, tagsToUse, cmd, channel.name, *message)
		}
	}
}

func (channel *Channel) applyModeFlag(client *Client, mode Mode,
	op ModeOp) bool {
	if !channel.ClientIsAtLeast(client, ChannelOperator) {
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

func (channel *Channel) applyModeMemberNoMutex(client *Client, mode Mode,
	op ModeOp, nick string) *ModeChange {
	// requires Lock()

	if nick == "" {
		//TODO(dan): shouldn't this be handled before it reaches this function?
		client.Send(nil, client.server.name, ERR_NEEDMOREPARAMS, "MODE", "Not enough parameters")
		return nil
	}

	casefoldedName, err := CasefoldName(nick)
	target := channel.server.clients.Get(casefoldedName)
	if err != nil || target == nil {
		client.Send(nil, client.server.name, ERR_NOSUCHNICK, client.nick, nick, "No such nick")
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
		return &ModeChange{
			op:   Add,
			mode: mode,
			arg:  nick,
		}

	case Remove:
		if !channel.members[target][mode] {
			return nil
		}
		channel.members[target][mode] = false
		return &ModeChange{
			op:   Remove,
			mode: mode,
			arg:  nick,
		}
	}
	return nil
}

// ShowMaskList shows the given list to the client.
func (channel *Channel) ShowMaskList(client *Client, mode Mode) {
	// choose appropriate modes
	var rpllist, rplendoflist string
	if mode == BanMask {
		rpllist = RPL_BANLIST
		rplendoflist = RPL_ENDOFBANLIST
	} else if mode == ExceptMask {
		rpllist = RPL_EXCEPTLIST
		rplendoflist = RPL_ENDOFEXCEPTLIST
	} else if mode == InviteMask {
		rpllist = RPL_INVITELIST
		rplendoflist = RPL_ENDOFINVITELIST
	}

	// send out responses
	for mask := range channel.lists[mode].masks {
		client.Send(nil, client.server.name, rpllist, client.nick, channel.name, mask)
	}
	client.Send(nil, client.server.name, rplendoflist, client.nick, channel.name, "End of list")
}

func (channel *Channel) applyModeMask(client *Client, mode Mode, op ModeOp, mask string) bool {
	list := channel.lists[mode]
	if list == nil {
		// This should never happen, but better safe than panicky.
		return false
	}

	if (op == List) || (mask == "") {
		channel.ShowMaskList(client, mode)
		return false
	}

	if !channel.ClientIsAtLeast(client, ChannelOperator) {
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

// Quit removes the given client from the channel, and also updates friends with the latest client list.
func (channel *Channel) Quit(client *Client, friends *ClientSet) {
	channel.membersMutex.Lock()
	defer channel.membersMutex.Unlock()

	channel.quitNoMutex(client)

	for friend := range channel.members {
		friends.Add(friend)
	}
}

func (channel *Channel) quitNoMutex(client *Client) {
	channel.members.Remove(client)
	client.channels.Remove(channel)

	if channel.isEmptyNoMutex() {
		channel.server.channels.Remove(channel)
	}
}

func (channel *Channel) kickNoMutex(client *Client, target *Client, comment string) {
	// needs a Lock()

	if !(client.flags[Operator] || channel.members.Has(client)) {
		client.Send(nil, client.server.name, ERR_NOTONCHANNEL, channel.name, "You're not on that channel")
		return
	}
	if !channel.clientIsAtLeastNoMutex(client, ChannelOperator) {
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
	channel.quitNoMutex(target)
}

// Invite invites the given client to the channel, if the inviter can do so.
func (channel *Channel) Invite(invitee *Client, inviter *Client) {
	if channel.flags[InviteOnly] && !channel.ClientIsAtLeast(inviter, ChannelOperator) {
		inviter.Send(nil, inviter.server.name, ERR_CHANOPRIVSNEEDED, channel.name, "You're not a channel operator")
		return
	}

	channel.membersMutex.RLock()
	defer channel.membersMutex.RUnlock()

	if !channel.members.Has(inviter) {
		inviter.Send(nil, inviter.server.name, ERR_NOTONCHANNEL, channel.name, "You're not on that channel")
		return
	}

	//TODO(dan): handle this more nicely, keep a list of last X invited channels on invitee rather than explicitly modifying the invite list?
	if channel.flags[InviteOnly] {
		channel.lists[InviteMask].Add(invitee.nickMaskCasefolded)
	}

	// send invite-notify
	for member := range channel.members {
		if member.capabilities[InviteNotify] && member != inviter && member != invitee && channel.ClientIsAtLeast(member, Halfop) {
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
