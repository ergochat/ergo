// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"strconv"
	"time"

	"sync"

	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/oragono/oragono/irc/caps"
	"github.com/oragono/oragono/irc/modes"
)

// Channel represents a channel that clients can join.
type Channel struct {
	flags             modes.ModeSet
	lists             map[modes.Mode]*UserMaskSet
	key               string
	members           MemberSet
	membersCache      []*Client  // allow iteration over channel members without holding the lock
	membersCacheMutex sync.Mutex // tier 2; see `regenerateMembersCache`
	metadata          *MetadataManager
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
		flags:       make(modes.ModeSet),
		lists: map[modes.Mode]*UserMaskSet{
			modes.BanMask:    NewUserMaskSet(),
			modes.ExceptMask: NewUserMaskSet(),
			modes.InviteMask: NewUserMaskSet(),
		},
		members:        make(MemberSet),
		metadata:       NewMetadataManager(),
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
		channel.lists[modes.BanMask].Add(mask)
	}
	for _, mask := range chanReg.Exceptlist {
		channel.lists[modes.ExceptMask].Add(mask)
	}
	for _, mask := range chanReg.Invitelist {
		channel.lists[modes.InviteMask].Add(mask)
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
		for mask := range channel.lists[modes.BanMask].masks {
			info.Banlist = append(info.Banlist, mask)
		}
		for mask := range channel.lists[modes.ExceptMask].masks {
			info.Exceptlist = append(info.Exceptlist, mask)
		}
		for mask := range channel.lists[modes.InviteMask].masks {
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
		return errChannelAlreadyRegistered
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
func (channel *Channel) Names(client *Client, rb *ResponseBuffer) {
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
			rb.Add(nil, client.server.name, RPL_NAMREPLY, client.nick, "=", channel.name, buffer)
			buffer = nick
			continue
		}

		buffer += " "
		buffer += nick
	}

	rb.Add(nil, client.server.name, RPL_NAMREPLY, client.nick, "=", channel.name, buffer)
	rb.Add(nil, client.server.name, RPL_ENDOFNAMES, client.nick, channel.name, client.t("End of NAMES list"))
}

// ClientIsAtLeast returns whether the client has at least the given channel privilege.
func (channel *Channel) ClientIsAtLeast(client *Client, permission modes.Mode) bool {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()

	// get voice, since it's not a part of ChannelPrivModes
	if channel.members.HasMode(client, permission) {
		return true
	}

	// check regular modes
	for _, mode := range modes.ChannelPrivModes {
		if channel.members.HasMode(client, mode) {
			return true
		}

		if mode == permission {
			break
		}
	}

	return false
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
	for _, mode := range modes.ChannelPrivModes {
		if clientModes[mode] {
			result = true
			// admins cannot kick other admins
			if mode == modes.ChannelAdmin && targetModes[modes.ChannelAdmin] {
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
	isMember := client.HasMode(modes.Operator) || channel.hasClient(client)
	showKey := isMember && (channel.key != "")
	showUserLimit := channel.userLimit > 0

	mods := "+"

	// flags with args
	if showKey {
		mods += modes.Key.String()
	}
	if showUserLimit {
		mods += modes.UserLimit.String()
	}

	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()

	// flags
	for mode := range channel.flags {
		mods += mode.String()
	}

	result = []string{mods}

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
func (channel *Channel) Join(client *Client, key string, rb *ResponseBuffer) {
	if channel.hasClient(client) {
		// already joined, no message needs to be sent
		return
	}

	if channel.IsFull() {
		rb.Add(nil, client.server.name, ERR_CHANNELISFULL, channel.name, fmt.Sprintf(client.t("Cannot join channel (+%s)"), "l"))
		return
	}

	if !channel.CheckKey(key) {
		rb.Add(nil, client.server.name, ERR_BADCHANNELKEY, channel.name, fmt.Sprintf(client.t("Cannot join channel (+%s)"), "k"))
		return
	}

	isInvited := channel.lists[modes.InviteMask].Match(client.nickMaskCasefolded)
	if channel.flags[modes.InviteOnly] && !isInvited {
		rb.Add(nil, client.server.name, ERR_INVITEONLYCHAN, channel.name, fmt.Sprintf(client.t("Cannot join channel (+%s)"), "i"))
		return
	}

	if channel.lists[modes.BanMask].Match(client.nickMaskCasefolded) &&
		!isInvited &&
		!channel.lists[modes.ExceptMask].Match(client.nickMaskCasefolded) {
		rb.Add(nil, client.server.name, ERR_BANNEDFROMCHAN, channel.name, fmt.Sprintf(client.t("Cannot join channel (+%s)"), "b"))
		return
	}

	client.server.logger.Debug("join", fmt.Sprintf("%s joined channel %s", client.nick, channel.name))

	for _, member := range channel.Members() {
		if member == client {
			if member.capabilities.Has(caps.ExtendedJoin) {
				rb.Add(nil, client.nickMaskString, "JOIN", channel.name, client.AccountName(), client.realname)
			} else {
				rb.Add(nil, client.nickMaskString, "JOIN", channel.name)
			}
		} else {
			if member.capabilities.Has(caps.ExtendedJoin) {
				member.Send(nil, client.nickMaskString, "JOIN", channel.name, client.AccountName(), client.realname)
			} else {
				member.Send(nil, client.nickMaskString, "JOIN", channel.name)
			}
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
	var givenMode *modes.Mode
	account := client.Account()
	cffounder, _ := CasefoldName(channel.registeredFounder)
	if account != "" && account == cffounder {
		givenMode = &modes.ChannelFounder
	} else if newChannel {
		givenMode = &modes.ChannelOperator
	}
	if givenMode != nil {
		channel.stateMutex.Lock()
		channel.members[client][*givenMode] = true
		channel.stateMutex.Unlock()
	}

	if client.capabilities.Has(caps.ExtendedJoin) {
		rb.Add(nil, client.nickMaskString, "JOIN", channel.name, client.AccountName(), client.realname)
	} else {
		rb.Add(nil, client.nickMaskString, "JOIN", channel.name)
	}
	// don't send topic when it's an entirely new channel
	if !newChannel {
		channel.SendTopic(client, rb)
	}
	channel.Names(client, rb)
	if givenMode != nil {
		for _, member := range channel.Members() {
			if member == client {
				rb.Add(nil, client.server.name, "MODE", channel.name, fmt.Sprintf("+%v", *givenMode), client.nick)
			} else {
				member.Send(nil, client.server.name, "MODE", channel.name, fmt.Sprintf("+%v", *givenMode), client.nick)
			}
		}
	}
}

// Part parts the given client from this channel, with the given message.
func (channel *Channel) Part(client *Client, message string, rb *ResponseBuffer) {
	if !channel.hasClient(client) {
		rb.Add(nil, client.server.name, ERR_NOTONCHANNEL, channel.name, client.t("You're not on that channel"))
		return
	}

	for _, member := range channel.Members() {
		if member == client {
			rb.Add(nil, client.nickMaskString, "PART", channel.name, message)
		} else {
			member.Send(nil, client.nickMaskString, "PART", channel.name, message)
		}
	}
	channel.Quit(client)

	client.server.logger.Debug("part", fmt.Sprintf("%s left channel %s", client.nick, channel.name))
}

// SendTopic sends the channel topic to the given client.
func (channel *Channel) SendTopic(client *Client, rb *ResponseBuffer) {
	if !channel.hasClient(client) {
		rb.Add(nil, client.server.name, ERR_NOTONCHANNEL, client.nick, channel.name, client.t("You're not on that channel"))
		return
	}

	channel.stateMutex.RLock()
	name := channel.name
	topic := channel.topic
	topicSetBy := channel.topicSetBy
	topicSetTime := channel.topicSetTime
	channel.stateMutex.RUnlock()

	if topic == "" {
		rb.Add(nil, client.server.name, RPL_NOTOPIC, client.nick, name, client.t("No topic is set"))
		return
	}

	rb.Add(nil, client.server.name, RPL_TOPIC, client.nick, name, topic)
	rb.Add(nil, client.server.name, RPL_TOPICTIME, client.nick, name, topicSetBy, strconv.FormatInt(topicSetTime.Unix(), 10))
}

// SetTopic sets the topic of this channel, if the client is allowed to do so.
func (channel *Channel) SetTopic(client *Client, topic string, rb *ResponseBuffer) {
	if !(client.flags[modes.Operator] || channel.hasClient(client)) {
		rb.Add(nil, client.server.name, ERR_NOTONCHANNEL, channel.name, client.t("You're not on that channel"))
		return
	}

	if channel.HasMode(modes.OpOnlyTopic) && !channel.ClientIsAtLeast(client, modes.ChannelOperator) {
		rb.Add(nil, client.server.name, ERR_CHANOPRIVSNEEDED, channel.name, client.t("You're not a channel operator"))
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
		if member == client {
			rb.Add(nil, client.nickMaskString, "TOPIC", channel.name, topic)
		} else {
			member.Send(nil, client.nickMaskString, "TOPIC", channel.name, topic)
		}
	}

	go channel.server.channelRegistry.StoreChannel(channel, false)
}

// CanSpeak returns true if the client can speak on this channel.
func (channel *Channel) CanSpeak(client *Client) bool {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()

	_, hasClient := channel.members[client]
	if channel.flags[modes.NoOutside] && !hasClient {
		return false
	}
	if channel.flags[modes.Moderated] && !channel.ClientIsAtLeast(client, modes.Voice) {
		return false
	}
	if channel.flags[modes.RegisteredOnly] && client.Account() == "" {
		return false
	}
	return true
}

// TagMsg sends a tag message to everyone in this channel who can accept them.
func (channel *Channel) TagMsg(msgid string, minPrefix *modes.Mode, clientOnlyTags *map[string]ircmsg.TagValue, client *Client, rb *ResponseBuffer) {
	channel.sendMessage(msgid, "TAGMSG", []caps.Capability{caps.MessageTags}, minPrefix, clientOnlyTags, client, nil, rb)
}

// sendMessage sends a given message to everyone on this channel.
func (channel *Channel) sendMessage(msgid, cmd string, requiredCaps []caps.Capability, minPrefix *modes.Mode, clientOnlyTags *map[string]ircmsg.TagValue, client *Client, message *string, rb *ResponseBuffer) {
	if !channel.CanSpeak(client) {
		rb.Add(nil, client.server.name, ERR_CANNOTSENDTOCHAN, channel.name, client.t("Cannot send to channel"))
		return
	}

	// for STATUSMSG
	var minPrefixMode modes.Mode
	if minPrefix != nil {
		minPrefixMode = *minPrefix
	}
	// send echo-message
	if client.capabilities.Has(caps.EchoMessage) {
		var messageTagsToUse *map[string]ircmsg.TagValue
		if client.capabilities.Has(caps.MessageTags) {
			messageTagsToUse = clientOnlyTags
		}

		if message == nil {
			rb.AddFromClient(msgid, client, messageTagsToUse, cmd, channel.name)
		} else {
			rb.AddFromClient(msgid, client, messageTagsToUse, cmd, channel.name, *message)
		}
	}
	for _, member := range channel.Members() {
		if minPrefix != nil && !channel.ClientIsAtLeast(member, minPrefixMode) {
			// STATUSMSG
			continue
		}
		// echo-message is handled above, so skip sending the msg to the user themselves as well
		if member == client {
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
func (channel *Channel) SplitPrivMsg(msgid string, minPrefix *modes.Mode, clientOnlyTags *map[string]ircmsg.TagValue, client *Client, message SplitMessage, rb *ResponseBuffer) {
	channel.sendSplitMessage(msgid, "PRIVMSG", minPrefix, clientOnlyTags, client, &message, rb)
}

// SplitNotice sends a private message to everyone in this channel.
func (channel *Channel) SplitNotice(msgid string, minPrefix *modes.Mode, clientOnlyTags *map[string]ircmsg.TagValue, client *Client, message SplitMessage, rb *ResponseBuffer) {
	channel.sendSplitMessage(msgid, "NOTICE", minPrefix, clientOnlyTags, client, &message, rb)
}

func (channel *Channel) sendSplitMessage(msgid, cmd string, minPrefix *modes.Mode, clientOnlyTags *map[string]ircmsg.TagValue, client *Client, message *SplitMessage, rb *ResponseBuffer) {
	if !channel.CanSpeak(client) {
		rb.Add(nil, client.server.name, ERR_CANNOTSENDTOCHAN, channel.name, client.t("Cannot send to channel"))
		return
	}

	// for STATUSMSG
	var minPrefixMode modes.Mode
	if minPrefix != nil {
		minPrefixMode = *minPrefix
	}
	// send echo-message
	if client.capabilities.Has(caps.EchoMessage) {
		var tagsToUse *map[string]ircmsg.TagValue
		if client.capabilities.Has(caps.MessageTags) {
			tagsToUse = clientOnlyTags
		}
		if message == nil {
			rb.AddFromClient(msgid, client, tagsToUse, cmd, channel.name)
		} else {
			rb.AddSplitMessageFromClient(msgid, client, tagsToUse, cmd, channel.name, *message)
		}
	}
	for _, member := range channel.Members() {
		if minPrefix != nil && !channel.ClientIsAtLeast(member, minPrefixMode) {
			// STATUSMSG
			continue
		}
		// echo-message is handled above, so skip sending the msg to the user themselves as well
		if member == client {
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

func (channel *Channel) applyModeMemberNoMutex(client *Client, mode modes.Mode, op modes.ModeOp, nick string, rb *ResponseBuffer) *modes.ModeChange {
	if nick == "" {
		//TODO(dan): shouldn't this be handled before it reaches this function?
		rb.Add(nil, client.server.name, ERR_NEEDMOREPARAMS, "MODE", client.t("Not enough parameters"))
		return nil
	}

	casefoldedName, err := CasefoldName(nick)
	target := channel.server.clients.Get(casefoldedName)
	if err != nil || target == nil {
		rb.Add(nil, client.server.name, ERR_NOSUCHNICK, client.nick, nick, client.t("No such nick"))
		return nil
	}

	channel.stateMutex.Lock()
	modeset, exists := channel.members[target]
	var already bool
	if exists {
		enable := op == modes.Add
		already = modeset[mode] == enable
		modeset[mode] = enable
	}
	channel.stateMutex.Unlock()

	if !exists {
		rb.Add(nil, client.server.name, ERR_USERNOTINCHANNEL, client.nick, channel.name, client.t("They aren't on that channel"))
		return nil
	} else if already {
		return nil
	} else {
		return &modes.ModeChange{
			Op:   op,
			Mode: mode,
			Arg:  nick,
		}
	}
}

// ShowMaskList shows the given list to the client.
func (channel *Channel) ShowMaskList(client *Client, mode modes.Mode, rb *ResponseBuffer) {
	// choose appropriate modes
	var rpllist, rplendoflist string
	if mode == modes.BanMask {
		rpllist = RPL_BANLIST
		rplendoflist = RPL_ENDOFBANLIST
	} else if mode == modes.ExceptMask {
		rpllist = RPL_EXCEPTLIST
		rplendoflist = RPL_ENDOFEXCEPTLIST
	} else if mode == modes.InviteMask {
		rpllist = RPL_INVITELIST
		rplendoflist = RPL_ENDOFINVITELIST
	}

	nick := client.Nick()
	channel.stateMutex.RLock()
	// XXX don't acquire any new locks in this section, besides Socket.Write
	for mask := range channel.lists[mode].masks {
		rb.Add(nil, client.server.name, rpllist, nick, channel.name, mask)
	}
	channel.stateMutex.RUnlock()

	rb.Add(nil, client.server.name, rplendoflist, nick, channel.name, client.t("End of list"))
}

func (channel *Channel) applyModeMask(client *Client, mode modes.Mode, op modes.ModeOp, mask string, rb *ResponseBuffer) bool {
	list := channel.lists[mode]
	if list == nil {
		// This should never happen, but better safe than panicky.
		return false
	}

	if (op == modes.List) || (mask == "") {
		channel.ShowMaskList(client, mode, rb)
		return false
	}

	if !channel.ClientIsAtLeast(client, modes.ChannelOperator) {
		rb.Add(nil, client.server.name, ERR_CHANOPRIVSNEEDED, channel.name, client.t("You're not a channel operator"))
		return false
	}

	if op == modes.Add {
		return list.Add(mask)
	}

	if op == modes.Remove {
		return list.Remove(mask)
	}

	return false
}

// Quit removes the given client from the channel
func (channel *Channel) Quit(client *Client) {
	channel.stateMutex.Lock()
	channel.members.Remove(client)
	empty := len(channel.members) == 0
	channel.stateMutex.Unlock()
	channel.regenerateMembersCache(false)

	client.removeChannel(channel)

	if empty {
		client.server.channels.Cleanup(channel)
	}
}

func (channel *Channel) Kick(client *Client, target *Client, comment string, rb *ResponseBuffer) {
	if !(client.flags[modes.Operator] || channel.hasClient(client)) {
		rb.Add(nil, client.server.name, ERR_NOTONCHANNEL, channel.name, client.t("You're not on that channel"))
		return
	}
	if !channel.ClientIsAtLeast(client, modes.ChannelOperator) {
		rb.Add(nil, client.server.name, ERR_CANNOTSENDTOCHAN, channel.name, client.t("Cannot send to channel"))
		return
	}
	if !channel.hasClient(target) {
		rb.Add(nil, client.server.name, ERR_USERNOTINCHANNEL, client.nick, channel.name, client.t("They aren't on that channel"))
		return
	}
	if !channel.ClientHasPrivsOver(client, target) {
		rb.Add(nil, client.server.name, ERR_CHANOPRIVSNEEDED, channel.name, client.t("You're not a channel operator"))
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
func (channel *Channel) Invite(invitee *Client, inviter *Client, rb *ResponseBuffer) {
	if channel.flags[modes.InviteOnly] && !channel.ClientIsAtLeast(inviter, modes.ChannelOperator) {
		rb.Add(nil, inviter.server.name, ERR_CHANOPRIVSNEEDED, channel.name, inviter.t("You're not a channel operator"))
		return
	}

	if !channel.hasClient(inviter) {
		rb.Add(nil, inviter.server.name, ERR_NOTONCHANNEL, channel.name, inviter.t("You're not on that channel"))
		return
	}

	//TODO(dan): handle this more nicely, keep a list of last X invited channels on invitee rather than explicitly modifying the invite list?
	if channel.flags[modes.InviteOnly] {
		nmc := invitee.NickCasefolded()
		channel.stateMutex.Lock()
		channel.lists[modes.InviteMask].Add(nmc)
		channel.stateMutex.Unlock()
	}

	for _, member := range channel.Members() {
		if member.capabilities.Has(caps.InviteNotify) && member != inviter && member != invitee && channel.ClientIsAtLeast(member, modes.Halfop) {
			member.Send(nil, inviter.NickMaskString(), "INVITE", invitee.Nick(), channel.name)
		}
	}

	//TODO(dan): should inviter.server.name here be inviter.nickMaskString ?
	rb.Add(nil, inviter.server.name, RPL_INVITING, invitee.nick, channel.name)
	invitee.Send(nil, inviter.nickMaskString, "INVITE", invitee.nick, channel.name)
	if invitee.flags[modes.Away] {
		rb.Add(nil, inviter.server.name, RPL_AWAY, invitee.nick, invitee.awayMessage)
	}
}
