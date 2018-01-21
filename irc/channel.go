// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"sync"

	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/oragono/oragono/irc/caps"
)

var (
	ChannelAlreadyRegistered = errors.New("Channel is already registered")
)

// Channel represents a channel that clients can join.
type Channel struct {
	flags             ModeSet
	lists             map[Mode]*UserMaskSet
	key               string
	members           MemberSet
	membersCache      []*Client  // allow iteration over channel members without holding the lock
	membersCacheMutex sync.Mutex // tier 2; see `regenerateMembersCache`
	name              string
	nameCasefolded    string
	server            *Server
	createdTime       time.Time
	registeredFounder string
	registeredTime    time.Time
	stateMutex        sync.RWMutex // tier 1
	topic             string
	topicSetBy        string
	topicSetTime      time.Time
	userLimit         uint64
}

// NewChannel creates a new channel from a `Server` and a `name`
// string, which must be unique on the server.
func NewChannel(s *Server, name string, addDefaultModes bool, regInfo *RegisteredChannel) *Channel {
	casefoldedName, err := CasefoldChannel(name)
	if err != nil {
		s.logger.Error("internal", fmt.Sprintf("Bad channel name %s: %v", name, err))
		return nil
	}

	channel := &Channel{
		createdTime: time.Now(), // may be overwritten by applyRegInfo
		flags:       make(ModeSet),
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
		for _, mode := range s.DefaultChannelModes() {
			channel.flags[mode] = true
		}
	}

	if regInfo != nil {
		channel.applyRegInfo(regInfo)
	}

	return channel
}

// read in channel state that was persisted in the DB
func (channel *Channel) applyRegInfo(chanReg *RegisteredChannel) {
	channel.registeredFounder = chanReg.Founder
	channel.registeredTime = chanReg.RegisteredAt
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

// obtain a consistent snapshot of the channel state that can be persisted to the DB
func (channel *Channel) ExportRegistration(includeLists bool) (info RegisteredChannel) {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()

	info.Name = channel.name
	info.Topic = channel.topic
	info.TopicSetBy = channel.topicSetBy
	info.TopicSetTime = channel.topicSetTime
	info.Founder = channel.registeredFounder
	info.RegisteredAt = channel.registeredTime

	if includeLists {
		for mask := range channel.lists[BanMask].masks {
			info.Banlist = append(info.Banlist, mask)
		}
		for mask := range channel.lists[ExceptMask].masks {
			info.Exceptlist = append(info.Exceptlist, mask)
		}
		for mask := range channel.lists[InviteMask].masks {
			info.Invitelist = append(info.Invitelist, mask)
		}
	}

	return
}

// SetRegistered registers the channel, returning an error if it was already registered.
func (channel *Channel) SetRegistered(founder string) error {
	channel.stateMutex.Lock()
	defer channel.stateMutex.Unlock()

	if channel.registeredFounder != "" {
		return ChannelAlreadyRegistered
	}
	channel.registeredFounder = founder
	channel.registeredTime = time.Now()
	return nil
}

// IsRegistered returns whether the channel is registered.
func (channel *Channel) IsRegistered() bool {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.registeredFounder != ""
}

func (channel *Channel) regenerateMembersCache(noLocksNeeded bool) {
	// this is eventually consistent even without holding stateMutex.Lock()
	// throughout the update; all updates to `members` while holding Lock()
	// have a serial order, so the call to `regenerateMembersCache` that
	// happens-after the last one will see *all* the updates. then,
	// `membersCacheMutex` ensures that this final read is correctly paired
	// with the final write to `membersCache`.
	if !noLocksNeeded {
		channel.membersCacheMutex.Lock()
		defer channel.membersCacheMutex.Unlock()
		channel.stateMutex.RLock()
	}

	result := make([]*Client, len(channel.members))
	i := 0
	for client := range channel.members {
		result[i] = client
		i++
	}
	if !noLocksNeeded {
		channel.stateMutex.RUnlock()
		channel.stateMutex.Lock()
	}
	channel.membersCache = result
	if !noLocksNeeded {
		channel.stateMutex.Unlock()
	}
}

// Names sends the list of users joined to the channel to the given client.
func (channel *Channel) Names(client *Client) {
	currentNicks := channel.nicks(client)
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
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()

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

func (channel *Channel) ClientPrefixes(client *Client, isMultiPrefix bool) string {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	modes, present := channel.members[client]
	if !present {
		return ""
	} else {
		return modes.Prefixes(isMultiPrefix)
	}
}

func (channel *Channel) ClientHasPrivsOver(client *Client, target *Client) bool {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()

	clientModes := channel.members[client]
	targetModes := channel.members[target]
	result := false
	for _, mode := range ChannelPrivModes {
		if clientModes[mode] {
			result = true
			// admins cannot kick other admins
			if mode == ChannelAdmin && targetModes[ChannelAdmin] {
				result = false
			}
			break
		} else if channel.members[target][mode] {
			break
		}
	}
	return result
}

func (channel *Channel) nicks(target *Client) []string {
	isMultiPrefix := (target != nil) && target.capabilities.Has(caps.MultiPrefix)
	isUserhostInNames := (target != nil) && target.capabilities.Has(caps.UserhostInNames)

	// slightly cumbersome: get the mutex and copy both the client pointers and
	// the mode prefixes
	channel.stateMutex.RLock()
	length := len(channel.members)
	clients := make([]*Client, length)
	result := make([]string, length)
	i := 0
	for client, modes := range channel.members {
		clients[i] = client
		result[i] = modes.Prefixes(isMultiPrefix)
		i++
	}
	channel.stateMutex.RUnlock()

	i = 0
	for i < length {
		if isUserhostInNames {
			result[i] += clients[i].NickMaskString()
		} else {
			result[i] += clients[i].Nick()
		}
		i++
	}

	return result
}

func (channel *Channel) hasClient(client *Client) bool {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	_, present := channel.members[client]
	return present
}

// <mode> <mode params>
func (channel *Channel) modeStrings(client *Client) (result []string) {
	isMember := client.HasMode(Operator) || channel.hasClient(client)
	showKey := isMember && (channel.key != "")
	showUserLimit := channel.userLimit > 0

	modes := "+"

	// flags with args
	if showKey {
		modes += Key.String()
	}
	if showUserLimit {
		modes += UserLimit.String()
	}

	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()

	// flags
	for mode := range channel.flags {
		modes += mode.String()
	}

	result = []string{modes}

	// args for flags with args: The order must match above to keep
	// positional arguments in place.
	if showKey {
		result = append(result, channel.key)
	}
	if showUserLimit {
		result = append(result, strconv.FormatUint(channel.userLimit, 10))
	}

	return
}

// IsFull returns true if this channel is at its' members limit.
func (channel *Channel) IsFull() bool {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return (channel.userLimit > 0) && (uint64(len(channel.members)) >= channel.userLimit)
}

// CheckKey returns true if the key is not set or matches the given key.
func (channel *Channel) CheckKey(key string) bool {
	return (channel.key == "") || (channel.key == key)
}

func (channel *Channel) IsEmpty() bool {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return len(channel.members) == 0
}

// Join joins the given client to this channel (if they can be joined).
//TODO(dan): /SAJOIN and maybe a ForceJoin function?
func (channel *Channel) Join(client *Client, key string) {
	if channel.hasClient(client) {
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

	for _, member := range channel.Members() {
		if member.capabilities.Has(caps.ExtendedJoin) {
			member.Send(nil, client.nickMaskString, "JOIN", channel.name, client.account.Name, client.realname)
		} else {
			member.Send(nil, client.nickMaskString, "JOIN", channel.name)
		}
	}

	channel.stateMutex.Lock()
	channel.members.Add(client)
	firstJoin := len(channel.members) == 1
	channel.stateMutex.Unlock()
	channel.regenerateMembersCache(false)

	client.addChannel(channel)

	// give channel mode if necessary
	newChannel := firstJoin && !channel.IsRegistered()
	var givenMode *Mode
	if client.AccountName() == channel.registeredFounder {
		givenMode = &ChannelFounder
	} else if newChannel {
		givenMode = &ChannelOperator
	}
	if givenMode != nil {
		channel.stateMutex.Lock()
		channel.members[client][*givenMode] = true
		channel.stateMutex.Unlock()
	}

	if client.capabilities.Has(caps.ExtendedJoin) {
		client.Send(nil, client.nickMaskString, "JOIN", channel.name, client.account.Name, client.realname)
	} else {
		client.Send(nil, client.nickMaskString, "JOIN", channel.name)
	}
	// don't send topic when it's an entirely new channel
	if !newChannel {
		channel.SendTopic(client)
	}
	channel.Names(client)
	if givenMode != nil {
		for _, member := range channel.Members() {
			member.Send(nil, client.server.name, "MODE", channel.name, fmt.Sprintf("+%v", *givenMode), client.nick)
		}
	}
}

// Part parts the given client from this channel, with the given message.
func (channel *Channel) Part(client *Client, message string) {
	if !channel.hasClient(client) {
		client.Send(nil, client.server.name, ERR_NOTONCHANNEL, channel.name, "You're not on that channel")
		return
	}

	for _, member := range channel.Members() {
		member.Send(nil, client.nickMaskString, "PART", channel.name, message)
	}
	channel.Quit(client)

	client.server.logger.Debug("part", fmt.Sprintf("%s left channel %s", client.nick, channel.name))
}

// SendTopic sends the channel topic to the given client.
func (channel *Channel) SendTopic(client *Client) {
	if !channel.hasClient(client) {
		client.Send(nil, client.server.name, ERR_NOTONCHANNEL, client.nick, channel.name, "You're not on that channel")
		return
	}

	channel.stateMutex.RLock()
	name := channel.name
	topic := channel.topic
	topicSetBy := channel.topicSetBy
	topicSetTime := channel.topicSetTime
	channel.stateMutex.RUnlock()

	if topic == "" {
		client.Send(nil, client.server.name, RPL_NOTOPIC, client.nick, name, "No topic is set")
		return
	}

	client.Send(nil, client.server.name, RPL_TOPIC, client.nick, name, topic)
	client.Send(nil, client.server.name, RPL_TOPICTIME, client.nick, name, topicSetBy, strconv.FormatInt(topicSetTime.Unix(), 10))
}

// SetTopic sets the topic of this channel, if the client is allowed to do so.
func (channel *Channel) SetTopic(client *Client, topic string) {
	if !(client.flags[Operator] || channel.hasClient(client)) {
		client.Send(nil, client.server.name, ERR_NOTONCHANNEL, channel.name, "You're not on that channel")
		return
	}

	if channel.HasMode(OpOnlyTopic) && !channel.ClientIsAtLeast(client, ChannelOperator) {
		client.Send(nil, client.server.name, ERR_CHANOPRIVSNEEDED, channel.name, "You're not a channel operator")
		return
	}

	if len(topic) > client.server.limits.TopicLen {
		topic = topic[:client.server.limits.TopicLen]
	}

	channel.stateMutex.Lock()
	channel.topic = topic
	channel.topicSetBy = client.nickMaskString
	channel.topicSetTime = time.Now()
	channel.stateMutex.Unlock()

	for _, member := range channel.Members() {
		member.Send(nil, client.nickMaskString, "TOPIC", channel.name, topic)
	}

	go channel.server.channelRegistry.StoreChannel(channel, false)
}

// CanSpeak returns true if the client can speak on this channel.
func (channel *Channel) CanSpeak(client *Client) bool {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()

	_, hasClient := channel.members[client]
	if channel.flags[NoOutside] && !hasClient {
		return false
	}
	if channel.flags[Moderated] && !channel.ClientIsAtLeast(client, Voice) {
		return false
	}
	if channel.flags[RegisteredOnly] && client.account == &NoAccount {
		return false
	}
	return true
}

// TagMsg sends a tag message to everyone in this channel who can accept them.
func (channel *Channel) TagMsg(msgid string, minPrefix *Mode, clientOnlyTags *map[string]ircmsg.TagValue, client *Client) {
	channel.sendMessage(msgid, "TAGMSG", []caps.Capability{caps.MessageTags}, minPrefix, clientOnlyTags, client, nil)
}

// sendMessage sends a given message to everyone on this channel.
func (channel *Channel) sendMessage(msgid, cmd string, requiredCaps []caps.Capability, minPrefix *Mode, clientOnlyTags *map[string]ircmsg.TagValue, client *Client, message *string) {
	if !channel.CanSpeak(client) {
		client.Send(nil, client.server.name, ERR_CANNOTSENDTOCHAN, channel.name, "Cannot send to channel")
		return
	}

	// for STATUSMSG
	var minPrefixMode Mode
	if minPrefix != nil {
		minPrefixMode = *minPrefix
	}
	for _, member := range channel.Members() {
		if minPrefix != nil && !channel.ClientIsAtLeast(member, minPrefixMode) {
			// STATUSMSG
			continue
		}
		if member == client && !client.capabilities.Has(caps.EchoMessage) {
			continue
		}

		canReceive := true
		for _, capName := range requiredCaps {
			if !member.capabilities.Has(capName) {
				canReceive = false
			}
		}
		if !canReceive {
			continue
		}

		var messageTagsToUse *map[string]ircmsg.TagValue
		if member.capabilities.Has(caps.MessageTags) {
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

	// for STATUSMSG
	var minPrefixMode Mode
	if minPrefix != nil {
		minPrefixMode = *minPrefix
	}
	for _, member := range channel.Members() {
		if minPrefix != nil && !channel.ClientIsAtLeast(member, minPrefixMode) {
			// STATUSMSG
			continue
		}
		if member == client && !client.capabilities.Has(caps.EchoMessage) {
			continue
		}
		var tagsToUse *map[string]ircmsg.TagValue
		if member.capabilities.Has(caps.MessageTags) {
			tagsToUse = clientOnlyTags
		}

		if message == nil {
			member.SendFromClient(msgid, client, tagsToUse, cmd, channel.name)
		} else {
			member.SendSplitMsgFromClient(msgid, client, tagsToUse, cmd, channel.name, *message)
		}
	}
}

func (channel *Channel) applyModeMemberNoMutex(client *Client, mode Mode,
	op ModeOp, nick string) *ModeChange {
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

	channel.stateMutex.Lock()
	modeset, exists := channel.members[target]
	var already bool
	if exists {
		enable := op == Add
		already = modeset[mode] == enable
		modeset[mode] = enable
	}
	channel.stateMutex.Unlock()

	if !exists {
		client.Send(nil, client.server.name, ERR_USERNOTINCHANNEL, client.nick, channel.name, "They aren't on that channel")
		return nil
	} else if already {
		return nil
	} else {
		return &ModeChange{
			op:   op,
			mode: mode,
			arg:  nick,
		}
	}
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

	nick := client.Nick()
	channel.stateMutex.RLock()
	// XXX don't acquire any new locks in this section, besides Socket.Write
	for mask := range channel.lists[mode].masks {
		client.Send(nil, client.server.name, rpllist, nick, channel.name, mask)
	}
	channel.stateMutex.RUnlock()

	client.Send(nil, client.server.name, rplendoflist, nick, channel.name, "End of list")
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

// Quit removes the given client from the channel
func (channel *Channel) Quit(client *Client) {
	channel.stateMutex.Lock()
	channel.members.Remove(client)
	channel.stateMutex.Unlock()
	channel.regenerateMembersCache(false)

	client.removeChannel(channel)
}

func (channel *Channel) Kick(client *Client, target *Client, comment string) {
	if !(client.flags[Operator] || channel.hasClient(client)) {
		client.Send(nil, client.server.name, ERR_NOTONCHANNEL, channel.name, "You're not on that channel")
		return
	}
	if !channel.ClientIsAtLeast(client, ChannelOperator) {
		client.Send(nil, client.server.name, ERR_CANNOTSENDTOCHAN, channel.name, "Cannot send to channel")
		return
	}
	if !channel.hasClient(target) {
		client.Send(nil, client.server.name, ERR_USERNOTINCHANNEL, client.nick, channel.name, "They aren't on that channel")
		return
	}
	if !channel.ClientHasPrivsOver(client, target) {
		client.Send(nil, client.server.name, ERR_CHANOPRIVSNEEDED, channel.name, "You're not a channel operator")
		return
	}

	kicklimit := client.server.Limits().KickLen
	if len(comment) > kicklimit {
		comment = comment[:kicklimit]
	}

	clientMask := client.NickMaskString()
	targetNick := target.Nick()
	for _, member := range channel.Members() {
		member.Send(nil, clientMask, "KICK", channel.name, targetNick, comment)
	}

	channel.Quit(target)
}

// Invite invites the given client to the channel, if the inviter can do so.
func (channel *Channel) Invite(invitee *Client, inviter *Client) {
	if channel.flags[InviteOnly] && !channel.ClientIsAtLeast(inviter, ChannelOperator) {
		inviter.Send(nil, inviter.server.name, ERR_CHANOPRIVSNEEDED, channel.name, "You're not a channel operator")
		return
	}

	if !channel.hasClient(inviter) {
		inviter.Send(nil, inviter.server.name, ERR_NOTONCHANNEL, channel.name, "You're not on that channel")
		return
	}

	//TODO(dan): handle this more nicely, keep a list of last X invited channels on invitee rather than explicitly modifying the invite list?
	if channel.flags[InviteOnly] {
		nmc := invitee.NickCasefolded()
		channel.stateMutex.Lock()
		channel.lists[InviteMask].Add(nmc)
		channel.stateMutex.Unlock()
	}

	for _, member := range channel.Members() {
		if member.capabilities.Has(caps.InviteNotify) && member != inviter && member != invitee && channel.ClientIsAtLeast(member, Halfop) {
			member.Send(nil, inviter.NickMaskString(), "INVITE", invitee.Nick(), channel.name)
		}
	}

	//TODO(dan): should inviter.server.name here be inviter.nickMaskString ?
	inviter.Send(nil, inviter.server.name, RPL_INVITING, invitee.nick, channel.name)
	invitee.Send(nil, inviter.nickMaskString, "INVITE", invitee.nick, channel.name)
	if invitee.flags[Away] {
		inviter.Send(nil, inviter.server.name, RPL_AWAY, invitee.nick, invitee.awayMessage)
	}
}
