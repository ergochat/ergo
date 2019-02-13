// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"sync"

	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/oragono/oragono/irc/caps"
	"github.com/oragono/oragono/irc/history"
	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/utils"
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
	userLimit         int
	accountToUMode    map[string]modes.Mode
	history           history.Buffer
}

// NewChannel creates a new channel from a `Server` and a `name`
// string, which must be unique on the server.
func NewChannel(s *Server, name string, regInfo *RegisteredChannel) *Channel {
	casefoldedName, err := CasefoldChannel(name)
	if err != nil {
		s.logger.Error("internal", "Bad channel name", name, err.Error())
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

	config := s.Config()

	if regInfo != nil {
		channel.applyRegInfo(regInfo)
	} else {
		for _, mode := range config.Channels.defaultModes {
			channel.flags.SetMode(mode, true)
		}
	}

	channel.history.Initialize(config.History.ChannelLength)

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
			buffer.Reset()
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
	clientModes := channel.members[client]
	channel.stateMutex.RUnlock()

	if clientModes == nil {
		return false
	}

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
		result = append(result, strconv.Itoa(channel.userLimit))
	}

	return
}

func (channel *Channel) IsEmpty() bool {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return len(channel.members) == 0
}

// Join joins the given client to this channel (if they can be joined).
func (channel *Channel) Join(client *Client, key string, isSajoin bool, rb *ResponseBuffer) {
	details := client.Details()

	channel.stateMutex.RLock()
	chname := channel.name
	chcfname := channel.nameCasefolded
	founder := channel.registeredFounder
	chkey := channel.key
	limit := channel.userLimit
	chcount := len(channel.members)
	_, alreadyJoined := channel.members[client]
	persistentMode := channel.accountToUMode[details.account]
	channel.stateMutex.RUnlock()

	if alreadyJoined {
		// no message needs to be sent
		return
	}

	// the founder can always join (even if they disabled auto +q on join);
	// anyone who automatically receives halfop or higher can always join
	hasPrivs := isSajoin || (founder != "" && founder == details.account) || (persistentMode != 0 && persistentMode != modes.Voice)

	if !hasPrivs && limit != 0 && chcount >= limit {
		rb.Add(nil, client.server.name, ERR_CHANNELISFULL, chname, fmt.Sprintf(client.t("Cannot join channel (+%s)"), "l"))
		return
	}

	if !hasPrivs && chkey != "" && !utils.SecretTokensMatch(chkey, key) {
		rb.Add(nil, client.server.name, ERR_BADCHANNELKEY, chname, fmt.Sprintf(client.t("Cannot join channel (+%s)"), "k"))
		return
	}

	isInvited := client.CheckInvited(chcfname) || channel.lists[modes.InviteMask].Match(details.nickMaskCasefolded)
	if !hasPrivs && channel.flags.HasMode(modes.InviteOnly) && !isInvited {
		rb.Add(nil, client.server.name, ERR_INVITEONLYCHAN, chname, fmt.Sprintf(client.t("Cannot join channel (+%s)"), "i"))
		return
	}

	if !hasPrivs && channel.lists[modes.BanMask].Match(details.nickMaskCasefolded) &&
		!isInvited &&
		!channel.lists[modes.ExceptMask].Match(details.nickMaskCasefolded) {
		rb.Add(nil, client.server.name, ERR_BANNEDFROMCHAN, chname, fmt.Sprintf(client.t("Cannot join channel (+%s)"), "b"))
		return
	}

	client.server.logger.Debug("join", fmt.Sprintf("%s joined channel %s", details.nick, chname))

	givenMode := func() (givenMode modes.Mode) {
		channel.joinPartMutex.Lock()
		defer channel.joinPartMutex.Unlock()

		func() {
			channel.stateMutex.Lock()
			defer channel.stateMutex.Unlock()

			channel.members.Add(client)
			firstJoin := len(channel.members) == 1
			newChannel := firstJoin && channel.registeredFounder == ""
			if newChannel {
				givenMode = modes.ChannelOperator
			} else {
				givenMode = persistentMode
			}
			if givenMode != 0 {
				channel.members[client].SetMode(givenMode, true)
			}
		}()

		channel.regenerateMembersCache()

		channel.history.Add(history.Item{
			Type:        history.Join,
			Nick:        details.nickMask,
			AccountName: details.accountName,
			Msgid:       details.realname,
		})

		return
	}()

	client.addChannel(channel)

	var modestr string
	if givenMode != 0 {
		modestr = fmt.Sprintf("+%v", givenMode)
	}

	for _, member := range channel.Members() {
		if member == client {
			continue
		}
		if member.capabilities.Has(caps.ExtendedJoin) {
			member.Send(nil, details.nickMask, "JOIN", chname, details.accountName, details.realname)
		} else {
			member.Send(nil, details.nickMask, "JOIN", chname)
		}
		if givenMode != 0 {
			member.Send(nil, client.server.name, "MODE", chname, modestr, details.nick)
		}
	}

	if client.capabilities.Has(caps.ExtendedJoin) {
		rb.Add(nil, details.nickMask, "JOIN", chname, details.accountName, details.realname)
	} else {
		rb.Add(nil, details.nickMask, "JOIN", chname)
	}

	channel.SendTopic(client, rb, false)

	channel.Names(client, rb)

	// TODO #259 can be implemented as Flush(false) (i.e., nonblocking) while holding joinPartMutex
	rb.Flush(true)

	replayLimit := channel.server.Config().History.AutoreplayOnJoin
	if replayLimit > 0 {
		items := channel.history.Latest(replayLimit)
		channel.replayHistoryItems(rb, items)
		rb.Flush(true)
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

	details := client.Details()
	for _, member := range channel.Members() {
		member.Send(nil, details.nickMask, "PART", chname, message)
	}
	rb.Add(nil, details.nickMask, "PART", chname, message)

	channel.history.Add(history.Item{
		Type:        history.Part,
		Nick:        details.nickMask,
		AccountName: details.accountName,
		Message:     utils.MakeSplitMessage(message, true),
	})

	client.server.logger.Debug("part", fmt.Sprintf("%s left channel %s", details.nick, chname))
}

// Resume is called after a successful global resume to:
// 1. Replace the old client with the new in the channel's data structures
// 2. Send JOIN and MODE lines to channel participants (including the new client)
// 3. Replay missed message history to the client
func (channel *Channel) Resume(newClient, oldClient *Client, timestamp time.Time) {
	now := time.Now()
	channel.resumeAndAnnounce(newClient, oldClient)
	if !timestamp.IsZero() {
		channel.replayHistoryForResume(newClient, timestamp, now)
	}
}

func (channel *Channel) resumeAndAnnounce(newClient, oldClient *Client) {
	var oldModeSet *modes.ModeSet

	func() {
		channel.joinPartMutex.Lock()
		defer channel.joinPartMutex.Unlock()

		defer channel.regenerateMembersCache()

		channel.stateMutex.Lock()
		defer channel.stateMutex.Unlock()

		newClient.channels[channel] = true
		oldModeSet = channel.members[oldClient]
		if oldModeSet == nil {
			oldModeSet = modes.NewModeSet()
		}
		channel.members.Remove(oldClient)
		channel.members[newClient] = oldModeSet
	}()

	// construct fake modestring if necessary
	oldModes := oldModeSet.String()
	if 0 < len(oldModes) {
		oldModes = "+" + oldModes
	}

	// send join for old clients
	nick := newClient.Nick()
	nickMask := newClient.NickMaskString()
	accountName := newClient.AccountName()
	realName := newClient.Realname()
	for _, member := range channel.Members() {
		if member.capabilities.Has(caps.Resume) {
			continue
		}

		if member.capabilities.Has(caps.ExtendedJoin) {
			member.Send(nil, nickMask, "JOIN", channel.name, accountName, realName)
		} else {
			member.Send(nil, nickMask, "JOIN", channel.name)
		}

		if 0 < len(oldModes) {
			member.Send(nil, channel.server.name, "MODE", channel.name, oldModes, nick)
		}
	}

	rb := NewResponseBuffer(newClient)
	// use blocking i/o to synchronize with the later history replay
	if newClient.capabilities.Has(caps.ExtendedJoin) {
		rb.Add(nil, nickMask, "JOIN", channel.name, accountName, realName)
	} else {
		rb.Add(nil, nickMask, "JOIN", channel.name)
	}
	channel.SendTopic(newClient, rb, false)
	channel.Names(newClient, rb)
	if 0 < len(oldModes) {
		rb.Add(nil, newClient.server.name, "MODE", channel.name, oldModes, nick)
	}
	rb.Send(true)
}

func (channel *Channel) replayHistoryForResume(newClient *Client, after time.Time, before time.Time) {
	items, complete := channel.history.Between(after, before, false, 0)
	rb := NewResponseBuffer(newClient)
	channel.replayHistoryItems(rb, items)
	if !complete && !newClient.resumeDetails.HistoryIncomplete {
		// warn here if we didn't warn already
		rb.Add(nil, "HistServ", "NOTICE", channel.Name(), newClient.t("Some additional message history may have been lost"))
	}
	rb.Send(true)
}

func stripMaskFromNick(nickMask string) (nick string) {
	index := strings.Index(nickMask, "!")
	if index == -1 {
		return
	}
	return nickMask[0:index]
}

func (channel *Channel) replayHistoryItems(rb *ResponseBuffer, items []history.Item) {
	chname := channel.Name()
	client := rb.target
	serverTime := client.capabilities.Has(caps.ServerTime)

	for _, item := range items {
		var tags Tags
		if serverTime {
			tags = ensureTag(tags, "time", item.Time.Format(IRCv3TimestampFormat))
		}

		switch item.Type {
		case history.Privmsg:
			rb.AddSplitMessageFromClient(item.Msgid, item.Nick, item.AccountName, tags, "PRIVMSG", chname, item.Message)
		case history.Notice:
			rb.AddSplitMessageFromClient(item.Msgid, item.Nick, item.AccountName, tags, "NOTICE", chname, item.Message)
		case history.Join:
			nick := stripMaskFromNick(item.Nick)
			var message string
			if item.AccountName == "*" {
				message = fmt.Sprintf(client.t("%s joined the channel"), nick)
			} else {
				message = fmt.Sprintf(client.t("%s [account: %s] joined the channel"), nick, item.AccountName)
			}
			rb.Add(tags, "HistServ", "PRIVMSG", chname, message)
		case history.Part:
			nick := stripMaskFromNick(item.Nick)
			message := fmt.Sprintf(client.t("%s left the channel (%s)"), nick, item.Message.Original)
			rb.Add(tags, "HistServ", "PRIVMSG", chname, message)
		case history.Quit:
			nick := stripMaskFromNick(item.Nick)
			message := fmt.Sprintf(client.t("%s quit (%s)"), nick, item.Message.Original)
			rb.Add(tags, "HistServ", "PRIVMSG", chname, message)
		case history.Kick:
			nick := stripMaskFromNick(item.Nick)
			// XXX Msgid is the kick target
			message := fmt.Sprintf(client.t("%s kicked %s (%s)"), nick, item.Msgid, item.Message.Original)
			rb.Add(tags, "HistServ", "PRIVMSG", chname, message)
		}
	}
}

// SendTopic sends the channel topic to the given client.
// `sendNoTopic` controls whether RPL_NOTOPIC is sent when the topic is unset
func (channel *Channel) SendTopic(client *Client, rb *ResponseBuffer, sendNoTopic bool) {
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
		if sendNoTopic {
			rb.Add(nil, client.server.name, RPL_NOTOPIC, client.nick, name, client.t("No topic is set"))
		}
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

		nickMaskString := client.NickMaskString()
		accountName := client.AccountName()
		if message == nil {
			rb.AddFromClient(msgid, nickMaskString, accountName, messageTagsToUse, cmd, channel.name)
		} else {
			rb.AddFromClient(msgid, nickMaskString, accountName, messageTagsToUse, cmd, channel.name, *message)
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
func (channel *Channel) SplitPrivMsg(msgid string, minPrefix *modes.Mode, clientOnlyTags *map[string]ircmsg.TagValue, client *Client, message utils.SplitMessage, rb *ResponseBuffer) {
	channel.sendSplitMessage(msgid, "PRIVMSG", history.Privmsg, minPrefix, clientOnlyTags, client, &message, rb)
}

// SplitNotice sends a private message to everyone in this channel.
func (channel *Channel) SplitNotice(msgid string, minPrefix *modes.Mode, clientOnlyTags *map[string]ircmsg.TagValue, client *Client, message utils.SplitMessage, rb *ResponseBuffer) {
	channel.sendSplitMessage(msgid, "NOTICE", history.Notice, minPrefix, clientOnlyTags, client, &message, rb)
}

func (channel *Channel) sendSplitMessage(msgid, cmd string, histType history.ItemType, minPrefix *modes.Mode, clientOnlyTags *map[string]ircmsg.TagValue, client *Client, message *utils.SplitMessage, rb *ResponseBuffer) {
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
		nickMaskString := client.NickMaskString()
		accountName := client.AccountName()
		if message == nil {
			rb.AddFromClient(msgid, nickMaskString, accountName, tagsToUse, cmd, channel.name)
		} else {
			rb.AddSplitMessageFromClient(msgid, nickMaskString, accountName, tagsToUse, cmd, channel.name, *message)
		}
	}

	nickmask := client.NickMaskString()
	account := client.AccountName()

	now := time.Now().UTC()

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
			member.sendFromClientInternal(false, now, msgid, nickmask, account, tagsToUse, cmd, channel.name)
		} else {
			member.sendSplitMsgFromClientInternal(false, now, msgid, nickmask, account, tagsToUse, cmd, channel.name, *message)
		}
	}

	channel.history.Add(history.Item{
		Type:        histType,
		Msgid:       msgid,
		Message:     *message,
		Nick:        nickmask,
		AccountName: account,
		Time:        now,
	})
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

	channel.history.Add(history.Item{
		Type:        history.Kick,
		Nick:        clientMask,
		Message:     utils.MakeSplitMessage(comment, true),
		AccountName: target.AccountName(),
		Msgid:       targetNick, // XXX abuse this field
	})

	channel.Quit(target)
}

// Invite invites the given client to the channel, if the inviter can do so.
func (channel *Channel) Invite(invitee *Client, inviter *Client, rb *ResponseBuffer) {
	chname := channel.Name()
	if channel.flags.HasMode(modes.InviteOnly) && !channel.ClientIsAtLeast(inviter, modes.ChannelOperator) {
		rb.Add(nil, inviter.server.name, ERR_CHANOPRIVSNEEDED, chname, inviter.t("You're not a channel operator"))
		return
	}

	if !channel.hasClient(inviter) {
		rb.Add(nil, inviter.server.name, ERR_NOTONCHANNEL, chname, inviter.t("You're not on that channel"))
		return
	}

	if channel.flags.HasMode(modes.InviteOnly) {
		invitee.Invite(channel.NameCasefolded())
	}

	for _, member := range channel.Members() {
		if member.capabilities.Has(caps.InviteNotify) && member != inviter && member != invitee && channel.ClientIsAtLeast(member, modes.Halfop) {
			member.Send(nil, inviter.NickMaskString(), "INVITE", invitee.Nick(), chname)
		}
	}

	rb.Add(nil, inviter.server.name, RPL_INVITING, inviter.Nick(), invitee.Nick(), chname)
	invitee.Send(nil, inviter.nickMaskString, "INVITE", invitee.nick, chname)
	if invitee.HasMode(modes.Away) {
		rb.Add(nil, inviter.server.name, RPL_AWAY, invitee.nick, invitee.awayMessage)
	}
}
