// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"bytes"
	"crypto/subtle"
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
	flags             *modes.ModeSet
	lists             map[modes.Mode]*UserMaskSet
	key               string
	members           MemberSet
	membersCache      []*Client // allow iteration over channel members without holding the lock
	name              string
	nameCasefolded    string
	server            *Server
	createdTime       time.Time
	registeredFounder string
	registeredTime    time.Time
	stateMutex        sync.RWMutex // tier 1
	joinPartMutex     sync.Mutex   // tier 3
	topic             string
	topicSetBy        string
	topicSetTime      time.Time
	userLimit         uint64
	accountToUMode    map[string]modes.Mode
}

// NewChannel creates a new channel from a `Server` and a `name`
// string, which must be unique on the server.
func NewChannel(s *Server, name string, regInfo *RegisteredChannel) *Channel {
	casefoldedName, err := CasefoldChannel(name)
	if err != nil {
		s.logger.Error("internal", fmt.Sprintf("Bad channel name %s: %v", name, err))
		return nil
	}

	channel := &Channel{
		createdTime: time.Now(), // may be overwritten by applyRegInfo
		flags:       modes.NewModeSet(),
		lists: map[modes.Mode]*UserMaskSet{
			modes.BanMask:    NewUserMaskSet(),
			modes.ExceptMask: NewUserMaskSet(),
			modes.InviteMask: NewUserMaskSet(),
		},
		members:        make(MemberSet),
		name:           name,
		nameCasefolded: casefoldedName,
		server:         s,
		accountToUMode: make(map[string]modes.Mode),
	}

	if regInfo != nil {
		channel.applyRegInfo(regInfo)
	} else {
		for _, mode := range s.DefaultChannelModes() {
			channel.flags.SetMode(mode, true)
		}
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
	channel.key = chanReg.Key

	for _, mode := range chanReg.Modes {
		channel.flags.SetMode(mode, true)
	}
	for _, mask := range chanReg.Banlist {
		channel.lists[modes.BanMask].Add(mask)
	}
	for _, mask := range chanReg.Exceptlist {
		channel.lists[modes.ExceptMask].Add(mask)
	}
	for _, mask := range chanReg.Invitelist {
		channel.lists[modes.InviteMask].Add(mask)
	}
	for account, mode := range chanReg.AccountToUMode {
		channel.accountToUMode[account] = mode
	}
}

// obtain a consistent snapshot of the channel state that can be persisted to the DB
func (channel *Channel) ExportRegistration(includeFlags uint) (info RegisteredChannel) {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()

	info.Name = channel.name
	info.Founder = channel.registeredFounder
	info.RegisteredAt = channel.registeredTime

	if includeFlags&IncludeTopic != 0 {
		info.Topic = channel.topic
		info.TopicSetBy = channel.topicSetBy
		info.TopicSetTime = channel.topicSetTime
	}

	if includeFlags&IncludeModes != 0 {
		info.Key = channel.key
		info.Modes = channel.flags.AllModes()
	}

	if includeFlags&IncludeLists != 0 {
		for mask := range channel.lists[modes.BanMask].masks {
			info.Banlist = append(info.Banlist, mask)
		}
		for mask := range channel.lists[modes.ExceptMask].masks {
			info.Exceptlist = append(info.Exceptlist, mask)
		}
		for mask := range channel.lists[modes.InviteMask].masks {
			info.Invitelist = append(info.Invitelist, mask)
		}
		info.AccountToUMode = make(map[string]modes.Mode)
		for account, mode := range channel.accountToUMode {
			info.AccountToUMode[account] = mode
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
	channel.accountToUMode[founder] = modes.ChannelFounder
	return nil
}

// SetUnregistered deletes the channel's registration information.
func (channel *Channel) SetUnregistered() {
	channel.stateMutex.Lock()
	defer channel.stateMutex.Unlock()

	channel.registeredFounder = ""
	var zeroTime time.Time
	channel.registeredTime = zeroTime
	channel.accountToUMode = make(map[string]modes.Mode)
}

// IsRegistered returns whether the channel is registered.
func (channel *Channel) IsRegistered() bool {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.registeredFounder != ""
}

func (channel *Channel) regenerateMembersCache() {
	channel.stateMutex.RLock()
	result := make([]*Client, len(channel.members))
	i := 0
	for client := range channel.members {
		result[i] = client
		i++
	}
	channel.stateMutex.RUnlock()

	channel.stateMutex.Lock()
	channel.membersCache = result
	channel.stateMutex.Unlock()
}

// Names sends the list of users joined to the channel to the given client.
func (channel *Channel) Names(client *Client, rb *ResponseBuffer) {
	isMultiPrefix := client.capabilities.Has(caps.MultiPrefix)
	isUserhostInNames := client.capabilities.Has(caps.UserhostInNames)

	maxNamLen := 480 - len(client.server.name) - len(client.Nick())
	var namesLines []string
	var buffer bytes.Buffer
	for _, target := range channel.Members() {
		var nick string
		if isUserhostInNames {
			nick = target.NickMaskString()
		} else {
			nick = target.Nick()
		}
		channel.stateMutex.RLock()
		modes := channel.members[target]
		channel.stateMutex.RUnlock()
		if modes == nil {
			continue
		}
		prefix := modes.Prefixes(isMultiPrefix)
		if buffer.Len()+len(nick)+len(prefix)+1 > maxNamLen {
			namesLines = append(namesLines, buffer.String())
			// memset(&buffer, 0, sizeof(bytes.Buffer));
			var newBuffer bytes.Buffer
			buffer = newBuffer
		}
		if buffer.Len() > 0 {
			buffer.WriteString(" ")
		}
		buffer.WriteString(prefix)
		buffer.WriteString(nick)
	}
	if buffer.Len() > 0 {
		namesLines = append(namesLines, buffer.String())
	}

	for _, line := range namesLines {
		if buffer.Len() > 0 {
			rb.Add(nil, client.server.name, RPL_NAMREPLY, client.nick, "=", channel.name, line)
		}
	}
	rb.Add(nil, client.server.name, RPL_ENDOFNAMES, client.nick, channel.name, client.t("End of NAMES list"))
}

// ClientIsAtLeast returns whether the client has at least the given channel privilege.
func (channel *Channel) ClientIsAtLeast(client *Client, permission modes.Mode) bool {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()

	clientModes := channel.members[client]

	for _, mode := range modes.ChannelUserModes {
		if clientModes.HasMode(mode) {
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
		if clientModes.HasMode(mode) {
			result = true
			// admins cannot kick other admins
			if mode == modes.ChannelAdmin && targetModes.HasMode(modes.ChannelAdmin) {
				result = false
			}
			break
		} else if targetModes.HasMode(mode) {
			break
		}
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

	mods += channel.flags.String()

	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()

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
	chkey := channel.Key()
	if chkey == "" {
		return true
	}

	return subtle.ConstantTimeCompare([]byte(key), []byte(chkey)) == 1
}

func (channel *Channel) IsEmpty() bool {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return len(channel.members) == 0
}

// Join joins the given client to this channel (if they can be joined).
func (channel *Channel) Join(client *Client, key string, isSajoin bool, rb *ResponseBuffer) {
	if channel.hasClient(client) {
		// already joined, no message needs to be sent
		return
	}

	channel.stateMutex.RLock()
	chname := channel.name
	founder := channel.registeredFounder
	channel.stateMutex.RUnlock()
	account := client.Account()
	hasPrivs := isSajoin || (founder != "" && founder == account)

	if !hasPrivs && channel.IsFull() {
		rb.Add(nil, client.server.name, ERR_CHANNELISFULL, chname, fmt.Sprintf(client.t("Cannot join channel (+%s)"), "l"))
		return
	}

	if !hasPrivs && !channel.CheckKey(key) {
		rb.Add(nil, client.server.name, ERR_BADCHANNELKEY, chname, fmt.Sprintf(client.t("Cannot join channel (+%s)"), "k"))
		return
	}

	isInvited := channel.lists[modes.InviteMask].Match(client.nickMaskCasefolded)
	if !hasPrivs && channel.flags.HasMode(modes.InviteOnly) && !isInvited {
		rb.Add(nil, client.server.name, ERR_INVITEONLYCHAN, chname, fmt.Sprintf(client.t("Cannot join channel (+%s)"), "i"))
		return
	}

	if !hasPrivs && channel.lists[modes.BanMask].Match(client.nickMaskCasefolded) &&
		!isInvited &&
		!channel.lists[modes.ExceptMask].Match(client.nickMaskCasefolded) {
		rb.Add(nil, client.server.name, ERR_BANNEDFROMCHAN, chname, fmt.Sprintf(client.t("Cannot join channel (+%s)"), "b"))
		return
	}

	client.server.logger.Debug("join", fmt.Sprintf("%s joined channel %s", client.nick, chname))

	newChannel, givenMode := func() (newChannel bool, givenMode modes.Mode) {
		channel.joinPartMutex.Lock()
		defer channel.joinPartMutex.Unlock()

		func() {
			channel.stateMutex.Lock()
			defer channel.stateMutex.Unlock()

			channel.members.Add(client)
			firstJoin := len(channel.members) == 1
			newChannel = firstJoin && channel.registeredFounder == ""
			if newChannel {
				givenMode = modes.ChannelOperator
			} else {
				givenMode = channel.accountToUMode[account]
			}
			if givenMode != 0 {
				channel.members[client].SetMode(givenMode, true)
			}
		}()

		channel.regenerateMembersCache()
		return
	}()

	client.addChannel(channel)

	nick := client.Nick()
	nickmask := client.NickMaskString()
	realname := client.Realname()
	accountName := client.AccountName()
	var modestr string
	if givenMode != 0 {
		modestr = fmt.Sprintf("+%v", givenMode)
	}

	for _, member := range channel.Members() {
		if member == client {
			continue
		}
		if member.capabilities.Has(caps.ExtendedJoin) {
			member.Send(nil, nickmask, "JOIN", chname, accountName, realname)
		} else {
			member.Send(nil, nickmask, "JOIN", chname)
		}
		if givenMode != 0 {
			member.Send(nil, client.server.name, "MODE", chname, modestr, nick)
		}
	}

	if client.capabilities.Has(caps.ExtendedJoin) {
		rb.Add(nil, nickmask, "JOIN", chname, accountName, realname)
	} else {
		rb.Add(nil, nickmask, "JOIN", chname)
	}

	// don't send topic when it's an entirely new channel
	if !newChannel {
		channel.SendTopic(client, rb)
	}

	channel.Names(client, rb)

	if givenMode != 0 {
		rb.Add(nil, client.server.name, "MODE", chname, modestr, nick)
	}
}

// Part parts the given client from this channel, with the given message.
func (channel *Channel) Part(client *Client, message string, rb *ResponseBuffer) {
	chname := channel.Name()
	if !channel.hasClient(client) {
		rb.Add(nil, client.server.name, ERR_NOTONCHANNEL, chname, client.t("You're not on that channel"))
		return
	}

	channel.Quit(client)

	nickmask := client.NickMaskString()
	for _, member := range channel.Members() {
		member.Send(nil, nickmask, "PART", chname, message)
	}
	rb.Add(nil, nickmask, "PART", chname, message)

	client.server.logger.Debug("part", fmt.Sprintf("%s left channel %s", client.nick, chname))
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
	if !(client.HasMode(modes.Operator) || channel.hasClient(client)) {
		rb.Add(nil, client.server.name, ERR_NOTONCHANNEL, channel.name, client.t("You're not on that channel"))
		return
	}

	if channel.flags.HasMode(modes.OpOnlyTopic) && !channel.ClientIsAtLeast(client, modes.ChannelOperator) {
		rb.Add(nil, client.server.name, ERR_CHANOPRIVSNEEDED, channel.name, client.t("You're not a channel operator"))
		return
	}

	topicLimit := client.server.Limits().TopicLen
	if len(topic) > topicLimit {
		topic = topic[:topicLimit]
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

	go channel.server.channelRegistry.StoreChannel(channel, IncludeTopic)
}

// CanSpeak returns true if the client can speak on this channel.
func (channel *Channel) CanSpeak(client *Client) bool {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()

	_, hasClient := channel.members[client]
	if channel.flags.HasMode(modes.NoOutside) && !hasClient {
		return false
	}
	if channel.flags.HasMode(modes.Moderated) && !channel.ClientIsAtLeast(client, modes.Voice) {
		return false
	}
	if channel.flags.HasMode(modes.RegisteredOnly) && client.Account() == "" {
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

func (channel *Channel) applyModeToMember(client *Client, mode modes.Mode, op modes.ModeOp, nick string, rb *ResponseBuffer) (result *modes.ModeChange) {
	casefoldedName, err := CasefoldName(nick)
	target := channel.server.clients.Get(casefoldedName)
	if err != nil || target == nil {
		rb.Add(nil, client.server.name, ERR_NOSUCHNICK, client.nick, nick, client.t("No such nick"))
		return nil
	}

	channel.stateMutex.Lock()
	modeset, exists := channel.members[target]
	if exists {
		if modeset.SetMode(mode, op == modes.Add) {
			result = &modes.ModeChange{
				Op:   op,
				Mode: mode,
				Arg:  nick,
			}
		}
	}
	channel.stateMutex.Unlock()

	if !exists {
		rb.Add(nil, client.server.name, ERR_USERNOTINCHANNEL, client.nick, channel.name, client.t("They aren't on that channel"))
	}
	return
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
	channelEmpty := func() bool {
		channel.joinPartMutex.Lock()
		defer channel.joinPartMutex.Unlock()

		channel.stateMutex.Lock()
		channel.members.Remove(client)
		channelEmpty := len(channel.members) == 0
		channel.stateMutex.Unlock()
		channel.regenerateMembersCache()
		return channelEmpty
	}()

	if channelEmpty {
		client.server.channels.Cleanup(channel)
	}
	client.removeChannel(channel)
}

func (channel *Channel) Kick(client *Client, target *Client, comment string, rb *ResponseBuffer) {
	if !(client.HasMode(modes.Operator) || channel.hasClient(client)) {
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
		rb.Add(nil, client.server.name, ERR_CHANOPRIVSNEEDED, channel.name, client.t("You don't have enough channel privileges"))
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
	if channel.flags.HasMode(modes.InviteOnly) && !channel.ClientIsAtLeast(inviter, modes.ChannelOperator) {
		rb.Add(nil, inviter.server.name, ERR_CHANOPRIVSNEEDED, channel.name, inviter.t("You're not a channel operator"))
		return
	}

	if !channel.hasClient(inviter) {
		rb.Add(nil, inviter.server.name, ERR_NOTONCHANNEL, channel.name, inviter.t("You're not on that channel"))
		return
	}

	//TODO(dan): handle this more nicely, keep a list of last X invited channels on invitee rather than explicitly modifying the invite list?
	if channel.flags.HasMode(modes.InviteOnly) {
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
	if invitee.HasMode(modes.Away) {
		rb.Add(nil, inviter.server.name, RPL_AWAY, invitee.nick, invitee.awayMessage)
	}
}
