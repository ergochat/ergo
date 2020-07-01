// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"sync"

	"github.com/oragono/oragono/irc/caps"
	"github.com/oragono/oragono/irc/history"
	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/utils"
)

type ChannelSettings struct {
	History HistoryStatus
}

// Channel represents a channel that clients can join.
type Channel struct {
	flags             modes.ModeSet
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
	transferPendingTo string
	topic             string
	topicSetBy        string
	topicSetTime      time.Time
	userLimit         int
	accountToUMode    map[string]modes.Mode
	history           history.Buffer
	stateMutex        sync.RWMutex    // tier 1
	writerSemaphore   utils.Semaphore // tier 1.5
	joinPartMutex     sync.Mutex      // tier 3
	ensureLoaded      utils.Once      // manages loading stored registration info from the database
	dirtyBits         uint
	settings          ChannelSettings
}

// NewChannel creates a new channel from a `Server` and a `name`
// string, which must be unique on the server.
func NewChannel(s *Server, name, casefoldedName string, registered bool) *Channel {
	config := s.Config()

	channel := &Channel{
		createdTime:    time.Now().UTC(), // may be overwritten by applyRegInfo
		members:        make(MemberSet),
		name:           name,
		nameCasefolded: casefoldedName,
		server:         s,
	}

	channel.initializeLists()
	channel.writerSemaphore.Initialize(1)
	channel.history.Initialize(0, 0)

	if !registered {
		channel.resizeHistory(config)
		for _, mode := range config.Channels.defaultModes {
			channel.flags.SetMode(mode, true)
		}
		// no loading to do, so "mark" the load operation as "done":
		channel.ensureLoaded.Do(func() {})
	} // else: modes will be loaded before first join

	return channel
}

func (channel *Channel) initializeLists() {
	channel.lists = map[modes.Mode]*UserMaskSet{
		modes.BanMask:    NewUserMaskSet(),
		modes.ExceptMask: NewUserMaskSet(),
		modes.InviteMask: NewUserMaskSet(),
	}
	channel.accountToUMode = make(map[string]modes.Mode)
}

// EnsureLoaded blocks until the channel's registration info has been loaded
// from the database.
func (channel *Channel) EnsureLoaded() {
	channel.ensureLoaded.Do(func() {
		nmc := channel.NameCasefolded()
		info, err := channel.server.channelRegistry.LoadChannel(nmc)
		if err == nil {
			channel.applyRegInfo(info)
		} else {
			channel.server.logger.Error("internal", "couldn't load channel", nmc, err.Error())
		}
	})
}

func (channel *Channel) IsLoaded() bool {
	return channel.ensureLoaded.Done()
}

func (channel *Channel) resizeHistory(config *Config) {
	status, _ := channel.historyStatus(config)
	if status == HistoryEphemeral {
		channel.history.Resize(config.History.ChannelLength, time.Duration(config.History.AutoresizeWindow))
	} else {
		channel.history.Resize(0, 0)
	}
}

// read in channel state that was persisted in the DB
func (channel *Channel) applyRegInfo(chanReg RegisteredChannel) {
	defer channel.resizeHistory(channel.server.Config())

	channel.stateMutex.Lock()
	defer channel.stateMutex.Unlock()

	channel.registeredFounder = chanReg.Founder
	channel.registeredTime = chanReg.RegisteredAt
	channel.topic = chanReg.Topic
	channel.topicSetBy = chanReg.TopicSetBy
	channel.topicSetTime = chanReg.TopicSetTime
	channel.name = chanReg.Name
	channel.createdTime = chanReg.RegisteredAt
	channel.key = chanReg.Key
	channel.userLimit = chanReg.UserLimit
	channel.settings = chanReg.Settings

	for _, mode := range chanReg.Modes {
		channel.flags.SetMode(mode, true)
	}
	for account, mode := range chanReg.AccountToUMode {
		channel.accountToUMode[account] = mode
	}
	channel.lists[modes.BanMask].SetMasks(chanReg.Bans)
	channel.lists[modes.InviteMask].SetMasks(chanReg.Invites)
	channel.lists[modes.ExceptMask].SetMasks(chanReg.Excepts)
}

// obtain a consistent snapshot of the channel state that can be persisted to the DB
func (channel *Channel) ExportRegistration(includeFlags uint) (info RegisteredChannel) {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()

	info.Name = channel.name
	info.NameCasefolded = channel.nameCasefolded
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
		info.UserLimit = channel.userLimit
	}

	if includeFlags&IncludeLists != 0 {
		info.Bans = channel.lists[modes.BanMask].Masks()
		info.Invites = channel.lists[modes.InviteMask].Masks()
		info.Excepts = channel.lists[modes.ExceptMask].Masks()
		info.AccountToUMode = make(map[string]modes.Mode)
		for account, mode := range channel.accountToUMode {
			info.AccountToUMode[account] = mode
		}
	}

	if includeFlags&IncludeSettings != 0 {
		info.Settings = channel.settings
	}

	return
}

// begin: asynchronous database writeback implementation, modeled on irc/socket.go

// MarkDirty marks part (or all) of a channel's data as needing to be written back
// to the database, then starts a writer goroutine if necessary.
// This is the equivalent of Socket.Write().
func (channel *Channel) MarkDirty(dirtyBits uint) {
	channel.stateMutex.Lock()
	isRegistered := channel.registeredFounder != ""
	channel.dirtyBits = channel.dirtyBits | dirtyBits
	channel.stateMutex.Unlock()
	if !isRegistered {
		return
	}

	channel.wakeWriter()
}

// IsClean returns whether a channel can be safely removed from the server.
// To avoid the obvious TOCTOU race condition, it must be called while holding
// ChannelManager's lock (that way, no one can join and make the channel dirty again
// between this method exiting and the actual deletion).
func (channel *Channel) IsClean() bool {
	config := channel.server.Config()

	if !channel.writerSemaphore.TryAcquire() {
		// a database write (which may fail) is in progress, the channel cannot be cleaned up
		return false
	}
	defer channel.writerSemaphore.Release()

	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	if len(channel.members) != 0 {
		return false
	}
	if channel.registeredFounder == "" {
		return true
	}
	// a registered channel must be fully written to the DB,
	// and not set to ephemeral history (#704)
	return channel.dirtyBits == 0 &&
		channelHistoryStatus(config, true, channel.settings.History) != HistoryEphemeral
}

func (channel *Channel) wakeWriter() {
	if channel.writerSemaphore.TryAcquire() {
		go channel.writeLoop()
	}
}

// equivalent of Socket.send()
func (channel *Channel) writeLoop() {
	for {
		// TODO(#357) check the error value of this and implement timed backoff
		channel.performWrite(0)
		channel.writerSemaphore.Release()

		channel.stateMutex.RLock()
		isDirty := channel.dirtyBits != 0
		isEmpty := len(channel.members) == 0
		channel.stateMutex.RUnlock()

		if !isDirty {
			if isEmpty {
				channel.server.channels.Cleanup(channel)
			}
			return // nothing to do
		} // else: isDirty, so we need to write again

		if !channel.writerSemaphore.TryAcquire() {
			return
		}
	}
}

// Store writes part (or all) of the channel's data back to the database,
// blocking until the write is complete. This is the equivalent of
// Socket.BlockingWrite.
func (channel *Channel) Store(dirtyBits uint) (err error) {
	defer func() {
		channel.stateMutex.Lock()
		isDirty := channel.dirtyBits != 0
		isEmpty := len(channel.members) == 0
		channel.stateMutex.Unlock()

		if isDirty {
			channel.wakeWriter()
		} else if isEmpty {
			channel.server.channels.Cleanup(channel)
		}
	}()

	channel.writerSemaphore.Acquire()
	defer channel.writerSemaphore.Release()
	return channel.performWrite(dirtyBits)
}

// do an individual write; equivalent of Socket.send()
func (channel *Channel) performWrite(additionalDirtyBits uint) (err error) {
	channel.stateMutex.Lock()
	dirtyBits := channel.dirtyBits | additionalDirtyBits
	channel.dirtyBits = 0
	isRegistered := channel.registeredFounder != ""
	channel.stateMutex.Unlock()

	if !isRegistered || dirtyBits == 0 {
		return
	}

	info := channel.ExportRegistration(dirtyBits)
	err = channel.server.channelRegistry.StoreChannel(info, dirtyBits)
	if err != nil {
		channel.stateMutex.Lock()
		channel.dirtyBits = channel.dirtyBits | dirtyBits
		channel.stateMutex.Unlock()
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
	channel.registeredTime = time.Now().UTC()
	channel.accountToUMode[founder] = modes.ChannelFounder
	return nil
}

// SetUnregistered deletes the channel's registration information.
func (channel *Channel) SetUnregistered(expectedFounder string) {
	channel.stateMutex.Lock()
	defer channel.stateMutex.Unlock()

	if channel.registeredFounder != expectedFounder {
		return
	}
	channel.registeredFounder = ""
	var zeroTime time.Time
	channel.registeredTime = zeroTime
	channel.accountToUMode = make(map[string]modes.Mode)
}

// implements `CHANSERV CLEAR #chan ACCESS` (resets bans, invites, excepts, and amodes)
func (channel *Channel) resetAccess() {
	defer channel.MarkDirty(IncludeLists)

	channel.stateMutex.Lock()
	defer channel.stateMutex.Unlock()
	channel.initializeLists()
	if channel.registeredFounder != "" {
		channel.accountToUMode[channel.registeredFounder] = modes.ChannelFounder
	}
}

// IsRegistered returns whether the channel is registered.
func (channel *Channel) IsRegistered() bool {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.registeredFounder != ""
}

type channelTransferStatus uint

const (
	channelTransferComplete channelTransferStatus = iota
	channelTransferPending
	channelTransferCancelled
	channelTransferFailed
)

// Transfer transfers ownership of a registered channel to a different account
func (channel *Channel) Transfer(client *Client, target string, hasPrivs bool) (status channelTransferStatus, err error) {
	status = channelTransferFailed
	defer func() {
		if status == channelTransferComplete && err == nil {
			channel.Store(IncludeAllAttrs)
		}
	}()

	cftarget, err := CasefoldName(target)
	if err != nil {
		err = errAccountDoesNotExist
		return
	}
	channel.stateMutex.Lock()
	defer channel.stateMutex.Unlock()
	if channel.registeredFounder == "" {
		err = errChannelNotOwnedByAccount
		return
	}
	if hasPrivs {
		channel.transferOwnership(cftarget)
		return channelTransferComplete, nil
	} else {
		if channel.registeredFounder == cftarget {
			// transferring back to yourself cancels a pending transfer
			channel.transferPendingTo = ""
			return channelTransferCancelled, nil
		} else {
			channel.transferPendingTo = cftarget
			return channelTransferPending, nil
		}
	}
}

func (channel *Channel) transferOwnership(newOwner string) {
	delete(channel.accountToUMode, channel.registeredFounder)
	channel.registeredFounder = newOwner
	channel.accountToUMode[channel.registeredFounder] = modes.ChannelFounder
	channel.transferPendingTo = ""
}

// AcceptTransfer implements `CS TRANSFER #chan ACCEPT`
func (channel *Channel) AcceptTransfer(client *Client) (err error) {
	defer func() {
		if err == nil {
			channel.Store(IncludeAllAttrs)
		}
	}()

	account := client.Account()
	if account == "" {
		return errAccountNotLoggedIn
	}
	channel.stateMutex.Lock()
	defer channel.stateMutex.Unlock()
	if account != channel.transferPendingTo {
		return errChannelTransferNotOffered
	}
	channel.transferOwnership(account)
	return nil
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
	isJoined := channel.hasClient(client)
	isOper := client.HasMode(modes.Operator)
	isMultiPrefix := rb.session.capabilities.Has(caps.MultiPrefix)
	isUserhostInNames := rb.session.capabilities.Has(caps.UserhostInNames)

	maxNamLen := 480 - len(client.server.name) - len(client.Nick())
	var namesLines []string
	var buffer strings.Builder
	if isJoined || !channel.flags.HasMode(modes.Secret) || isOper {
		for _, target := range channel.Members() {
			var nick string
			if isUserhostInNames {
				nick = target.NickMaskString()
			} else {
				nick = target.Nick()
			}
			channel.stateMutex.RLock()
			modeSet := channel.members[target]
			channel.stateMutex.RUnlock()
			if modeSet == nil {
				continue
			}
			if !isJoined && target.HasMode(modes.Invisible) && !isOper {
				continue
			}
			prefix := modeSet.Prefixes(isMultiPrefix)
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
	}

	for _, line := range namesLines {
		if buffer.Len() > 0 {
			rb.Add(nil, client.server.name, RPL_NAMREPLY, client.nick, "=", channel.name, line)
		}
	}
	rb.Add(nil, client.server.name, RPL_ENDOFNAMES, client.nick, channel.name, client.t("End of NAMES list"))
}

// does `clientMode` give you privileges to grant/remove `targetMode` to/from people,
// or to kick them?
func channelUserModeHasPrivsOver(clientMode modes.Mode, targetMode modes.Mode) bool {
	switch clientMode {
	case modes.ChannelFounder:
		return true
	case modes.ChannelAdmin, modes.ChannelOperator:
		// admins cannot kick other admins, operators *can* kick other operators
		return targetMode != modes.ChannelFounder && targetMode != modes.ChannelAdmin
	case modes.Halfop:
		// halfops cannot kick other halfops
		return targetMode == modes.Voice || targetMode == modes.Mode(0)
	default:
		// voice and unprivileged cannot kick anyone
		return false
	}
}

// ClientIsAtLeast returns whether the client has at least the given channel privilege.
func (channel *Channel) ClientIsAtLeast(client *Client, permission modes.Mode) bool {
	channel.stateMutex.RLock()
	clientModes := channel.members[client]
	founder := channel.registeredFounder
	channel.stateMutex.RUnlock()

	if founder != "" && founder == client.Account() {
		return true
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

func (channel *Channel) ClientStatus(client *Client) (present bool, cModes modes.Modes) {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	modes, present := channel.members[client]
	return present, modes.AllModes()
}

func (channel *Channel) ClientHasPrivsOver(client *Client, target *Client) bool {
	channel.stateMutex.RLock()
	founder := channel.registeredFounder
	clientModes := channel.members[client]
	targetModes := channel.members[target]
	channel.stateMutex.RUnlock()

	if founder != "" && founder == client.Account() {
		// #950: founder can kick or whatever without actually having the +q mode
		return true
	}

	return channelUserModeHasPrivsOver(clientModes.HighestChannelUserMode(), targetModes.HighestChannelUserMode())
}

func (channel *Channel) hasClient(client *Client) bool {
	channel.stateMutex.RLock()
	_, present := channel.members[client]
	channel.stateMutex.RUnlock()
	return present
}

// <mode> <mode params>
func (channel *Channel) modeStrings(client *Client) (result []string) {
	hasPrivs := client.HasMode(modes.Operator)

	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()

	isMember := hasPrivs || channel.members[client] != nil
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

// figure out where history is being stored: persistent, ephemeral, or neither
// target is only needed if we're doing persistent history
func (channel *Channel) historyStatus(config *Config) (status HistoryStatus, target string) {
	if !config.History.Enabled {
		return HistoryDisabled, ""
	}

	channel.stateMutex.RLock()
	target = channel.nameCasefolded
	historyStatus := channel.settings.History
	registered := channel.registeredFounder != ""
	channel.stateMutex.RUnlock()

	return channelHistoryStatus(config, registered, historyStatus), target
}

func channelHistoryStatus(config *Config, registered bool, storedStatus HistoryStatus) (result HistoryStatus) {
	if !config.History.Enabled {
		return HistoryDisabled
	}

	// ephemeral history: either the channel owner explicitly set the ephemeral preference,
	// or persistent history is disabled for unregistered channels
	if registered {
		return historyEnabled(config.History.Persistent.RegisteredChannels, storedStatus)
	} else {
		if config.History.Persistent.UnregisteredChannels {
			return HistoryPersistent
		} else {
			return HistoryEphemeral
		}
	}
}

func (channel *Channel) AddHistoryItem(item history.Item, account string) (err error) {
	if !item.IsStorable() {
		return
	}

	status, target := channel.historyStatus(channel.server.Config())
	if status == HistoryPersistent {
		err = channel.server.historyDB.AddChannelItem(target, item, account)
	} else if status == HistoryEphemeral {
		channel.history.Add(item)
	}
	return
}

// Join joins the given client to this channel (if they can be joined).
func (channel *Channel) Join(client *Client, key string, isSajoin bool, rb *ResponseBuffer) error {
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
		return nil
	}

	// 0. SAJOIN always succeeds
	// 1. the founder can always join (even if they disabled auto +q on join)
	// 2. anyone who automatically receives halfop or higher can always join
	// 3. people invited with INVITE can join
	hasPrivs := isSajoin || (founder != "" && founder == details.account) ||
		(persistentMode != 0 && persistentMode != modes.Voice) ||
		client.CheckInvited(chcfname)
	if !hasPrivs {
		if limit != 0 && chcount >= limit {
			return errLimitExceeded
		}

		if chkey != "" && !utils.SecretTokensMatch(chkey, key) {
			return errWrongChannelKey
		}

		if channel.flags.HasMode(modes.InviteOnly) &&
			!channel.lists[modes.InviteMask].Match(details.nickMaskCasefolded) {
			return errInviteOnly
		}

		if channel.lists[modes.BanMask].Match(details.nickMaskCasefolded) &&
			!channel.lists[modes.ExceptMask].Match(details.nickMaskCasefolded) &&
			!channel.lists[modes.InviteMask].Match(details.nickMaskCasefolded) {
			return errBanned
		}

		if channel.flags.HasMode(modes.RegisteredOnly) && details.account == "" {
			return errRegisteredOnly
		}
	}

	if joinErr := client.addChannel(channel, rb == nil); joinErr != nil {
		return joinErr
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

		return
	}()

	var message utils.SplitMessage
	// no history item for fake persistent joins
	if rb != nil {
		message = utils.MakeMessage("")
		histItem := history.Item{
			Type:        history.Join,
			Nick:        details.nickMask,
			AccountName: details.accountName,
			Message:     message,
		}
		histItem.Params[0] = details.realname
		channel.AddHistoryItem(histItem, details.account)
	}

	if rb == nil {
		return nil
	}

	var modestr string
	if givenMode != 0 {
		modestr = fmt.Sprintf("+%v", givenMode)
	}

	for _, member := range channel.Members() {
		for _, session := range member.Sessions() {
			if session == rb.session {
				continue
			} else if client == session.client {
				channel.playJoinForSession(session)
				continue
			}
			if session.capabilities.Has(caps.ExtendedJoin) {
				session.sendFromClientInternal(false, message.Time, message.Msgid, details.nickMask, details.accountName, nil, "JOIN", chname, details.accountName, details.realname)
			} else {
				session.sendFromClientInternal(false, message.Time, message.Msgid, details.nickMask, details.accountName, nil, "JOIN", chname)
			}
			if givenMode != 0 {
				session.Send(nil, client.server.name, "MODE", chname, modestr, details.nick)
			}
		}
	}

	if rb.session.capabilities.Has(caps.ExtendedJoin) {
		rb.AddFromClient(message.Time, message.Msgid, details.nickMask, details.accountName, nil, "JOIN", chname, details.accountName, details.realname)
	} else {
		rb.AddFromClient(message.Time, message.Msgid, details.nickMask, details.accountName, nil, "JOIN", chname)
	}

	if rb.session.client == client {
		// don't send topic and names for a SAJOIN of a different client
		channel.SendTopic(client, rb, false)
		channel.Names(client, rb)
	}

	// TODO #259 can be implemented as Flush(false) (i.e., nonblocking) while holding joinPartMutex
	rb.Flush(true)

	channel.autoReplayHistory(client, rb, message.Msgid)
	return nil
}

func (channel *Channel) autoReplayHistory(client *Client, rb *ResponseBuffer, skipMsgid string) {
	// autoreplay any messages as necessary
	var items []history.Item

	var start, end time.Time
	if rb.session.zncPlaybackTimes.ValidFor(channel.NameCasefolded()) {
		start, end = rb.session.zncPlaybackTimes.start, rb.session.zncPlaybackTimes.end
	} else if !rb.session.autoreplayMissedSince.IsZero() {
		// we already checked for history caps in `playReattachMessages`
		start = time.Now().UTC()
		end = rb.session.autoreplayMissedSince
	}

	if !start.IsZero() || !end.IsZero() {
		_, seq, _ := channel.server.GetHistorySequence(channel, client, "")
		if seq != nil {
			zncMax := channel.server.Config().History.ZNCMax
			items, _, _ = seq.Between(history.Selector{Time: start}, history.Selector{Time: end}, zncMax)
		}
	} else if !rb.session.HasHistoryCaps() {
		var replayLimit int
		customReplayLimit := client.AccountSettings().AutoreplayLines
		if customReplayLimit != nil {
			replayLimit = *customReplayLimit
			maxLimit := channel.server.Config().History.ChathistoryMax
			if maxLimit < replayLimit {
				replayLimit = maxLimit
			}
		} else {
			replayLimit = channel.server.Config().History.AutoreplayOnJoin
		}
		if 0 < replayLimit {
			_, seq, _ := channel.server.GetHistorySequence(channel, client, "")
			if seq != nil {
				items, _, _ = seq.Between(history.Selector{}, history.Selector{}, replayLimit)
			}
		}
	}
	// remove the client's own JOIN line from the replay
	numItems := len(items)
	for i := len(items) - 1; 0 <= i; i-- {
		if items[i].Message.Msgid == skipMsgid {
			// zero'ed items will not be replayed because their `Type` field is not recognized
			items[i] = history.Item{}
			numItems--
			break
		}
	}
	if 0 < numItems {
		channel.replayHistoryItems(rb, items, true)
		rb.Flush(true)
	}
}

// plays channel join messages (the JOIN line, topic, and names) to a session.
// this is used when attaching a new session to an existing client that already has
// channels, and also when one session of a client initiates a JOIN and the other
// sessions need to receive the state change
func (channel *Channel) playJoinForSession(session *Session) {
	client := session.client
	sessionRb := NewResponseBuffer(session)
	details := client.Details()
	if session.capabilities.Has(caps.ExtendedJoin) {
		sessionRb.Add(nil, details.nickMask, "JOIN", channel.Name(), details.accountName, details.realname)
	} else {
		sessionRb.Add(nil, details.nickMask, "JOIN", channel.Name())
	}
	channel.SendTopic(client, sessionRb, false)
	channel.Names(client, sessionRb)
	sessionRb.Send(false)
}

// Part parts the given client from this channel, with the given message.
func (channel *Channel) Part(client *Client, message string, rb *ResponseBuffer) {
	chname := channel.Name()
	if !channel.hasClient(client) {
		rb.Add(nil, client.server.name, ERR_NOTONCHANNEL, client.Nick(), chname, client.t("You're not on that channel"))
		return
	}

	channel.Quit(client)

	splitMessage := utils.MakeMessage(message)

	details := client.Details()
	params := make([]string, 1, 2)
	params[0] = chname
	if message != "" {
		params = append(params, message)
	}
	for _, member := range channel.Members() {
		member.sendFromClientInternal(false, splitMessage.Time, splitMessage.Msgid, details.nickMask, details.accountName, nil, "PART", params...)
	}
	rb.AddFromClient(splitMessage.Time, splitMessage.Msgid, details.nickMask, details.accountName, nil, "PART", params...)
	for _, session := range client.Sessions() {
		if session != rb.session {
			session.sendFromClientInternal(false, splitMessage.Time, splitMessage.Msgid, details.nickMask, details.accountName, nil, "PART", params...)
		}
	}

	channel.AddHistoryItem(history.Item{
		Type:        history.Part,
		Nick:        details.nickMask,
		AccountName: details.accountName,
		Message:     splitMessage,
	}, details.account)

	client.server.logger.Debug("part", fmt.Sprintf("%s left channel %s", details.nick, chname))
}

// Resume is called after a successful global resume to:
// 1. Replace the old client with the new in the channel's data structures
// 2. Send JOIN and MODE lines to channel participants (including the new client)
// 3. Replay missed message history to the client
func (channel *Channel) Resume(session *Session, timestamp time.Time) {
	channel.resumeAndAnnounce(session)
	if !timestamp.IsZero() {
		channel.replayHistoryForResume(session, timestamp, time.Time{})
	}
}

func (channel *Channel) resumeAndAnnounce(session *Session) {
	channel.stateMutex.RLock()
	modeSet := channel.members[session.client]
	channel.stateMutex.RUnlock()
	if modeSet == nil {
		return
	}
	oldModes := modeSet.String()
	if 0 < len(oldModes) {
		oldModes = "+" + oldModes
	}

	// send join for old clients
	chname := channel.Name()
	details := session.client.Details()
	for _, member := range channel.Members() {
		for _, session := range member.Sessions() {
			if session.capabilities.Has(caps.Resume) {
				continue
			}

			if session.capabilities.Has(caps.ExtendedJoin) {
				session.Send(nil, details.nickMask, "JOIN", chname, details.accountName, details.realname)
			} else {
				session.Send(nil, details.nickMask, "JOIN", chname)
			}

			if 0 < len(oldModes) {
				session.Send(nil, channel.server.name, "MODE", chname, oldModes, details.nick)
			}
		}
	}

	rb := NewResponseBuffer(session)
	// use blocking i/o to synchronize with the later history replay
	if rb.session.capabilities.Has(caps.ExtendedJoin) {
		rb.Add(nil, details.nickMask, "JOIN", channel.name, details.accountName, details.realname)
	} else {
		rb.Add(nil, details.nickMask, "JOIN", channel.name)
	}
	channel.SendTopic(session.client, rb, false)
	channel.Names(session.client, rb)
	rb.Send(true)
}

func (channel *Channel) replayHistoryForResume(session *Session, after time.Time, before time.Time) {
	var items []history.Item
	var complete bool
	afterS, beforeS := history.Selector{Time: after}, history.Selector{Time: before}
	_, seq, _ := channel.server.GetHistorySequence(channel, session.client, "")
	if seq != nil {
		items, complete, _ = seq.Between(afterS, beforeS, channel.server.Config().History.ZNCMax)
	}
	rb := NewResponseBuffer(session)
	if len(items) != 0 {
		channel.replayHistoryItems(rb, items, false)
	}
	if !complete && !session.resumeDetails.HistoryIncomplete {
		// warn here if we didn't warn already
		rb.Add(nil, histServMask, "NOTICE", channel.Name(), session.client.t("Some additional message history may have been lost"))
	}
	rb.Send(true)
}

func stripMaskFromNick(nickMask string) (nick string) {
	index := strings.Index(nickMask, "!")
	if index == -1 {
		return nickMask
	}
	return nickMask[0:index]
}

func (channel *Channel) replayHistoryItems(rb *ResponseBuffer, items []history.Item, autoreplay bool) {
	// send an empty batch if necessary, as per the CHATHISTORY spec
	chname := channel.Name()
	client := rb.target
	eventPlayback := rb.session.capabilities.Has(caps.EventPlayback)
	extendedJoin := rb.session.capabilities.Has(caps.ExtendedJoin)
	var playJoinsAsPrivmsg bool
	if !eventPlayback {
		switch client.AccountSettings().ReplayJoins {
		case ReplayJoinsCommandsOnly:
			playJoinsAsPrivmsg = !autoreplay
		case ReplayJoinsAlways:
			playJoinsAsPrivmsg = true
		case ReplayJoinsNever:
			playJoinsAsPrivmsg = false
		}
	}

	batchID := rb.StartNestedHistoryBatch(chname)
	defer rb.EndNestedBatch(batchID)

	for _, item := range items {
		nick := stripMaskFromNick(item.Nick)
		switch item.Type {
		case history.Privmsg:
			rb.AddSplitMessageFromClient(item.Nick, item.AccountName, item.Tags, "PRIVMSG", chname, item.Message)
		case history.Notice:
			rb.AddSplitMessageFromClient(item.Nick, item.AccountName, item.Tags, "NOTICE", chname, item.Message)
		case history.Tagmsg:
			if eventPlayback {
				rb.AddSplitMessageFromClient(item.Nick, item.AccountName, item.Tags, "TAGMSG", chname, item.Message)
			}
		case history.Join:
			if eventPlayback {
				if extendedJoin {
					rb.AddFromClient(item.Message.Time, item.Message.Msgid, item.Nick, item.AccountName, nil, "JOIN", chname, item.AccountName, item.Params[0])
				} else {
					rb.AddFromClient(item.Message.Time, item.Message.Msgid, item.Nick, item.AccountName, nil, "JOIN", chname)
				}
			} else {
				if !playJoinsAsPrivmsg {
					continue // #474
				}
				var message string
				if item.AccountName == "*" {
					message = fmt.Sprintf(client.t("%s joined the channel"), nick)
				} else {
					message = fmt.Sprintf(client.t("%[1]s [account: %[2]s] joined the channel"), nick, item.AccountName)
				}
				rb.AddFromClient(item.Message.Time, utils.MungeSecretToken(item.Message.Msgid), histServMask, "*", nil, "PRIVMSG", chname, message)
			}
		case history.Part:
			if eventPlayback {
				rb.AddFromClient(item.Message.Time, item.Message.Msgid, item.Nick, item.AccountName, nil, "PART", chname, item.Message.Message)
			} else {
				if !playJoinsAsPrivmsg {
					continue // #474
				}
				message := fmt.Sprintf(client.t("%[1]s left the channel (%[2]s)"), nick, item.Message.Message)
				rb.AddFromClient(item.Message.Time, utils.MungeSecretToken(item.Message.Msgid), histServMask, "*", nil, "PRIVMSG", chname, message)
			}
		case history.Kick:
			if eventPlayback {
				rb.AddFromClient(item.Message.Time, item.Message.Msgid, item.Nick, item.AccountName, nil, "KICK", chname, item.Params[0], item.Message.Message)
			} else {
				message := fmt.Sprintf(client.t("%[1]s kicked %[2]s (%[3]s)"), nick, item.Params[0], item.Message.Message)
				rb.AddFromClient(item.Message.Time, utils.MungeSecretToken(item.Message.Msgid), histServMask, "*", nil, "PRIVMSG", chname, message)
			}
		case history.Quit:
			if eventPlayback {
				rb.AddFromClient(item.Message.Time, item.Message.Msgid, item.Nick, item.AccountName, nil, "QUIT", item.Message.Message)
			} else {
				if !playJoinsAsPrivmsg {
					continue // #474
				}
				message := fmt.Sprintf(client.t("%[1]s quit (%[2]s)"), nick, item.Message.Message)
				rb.AddFromClient(item.Message.Time, utils.MungeSecretToken(item.Message.Msgid), histServMask, "*", nil, "PRIVMSG", chname, message)
			}
		case history.Nick:
			if eventPlayback {
				rb.AddFromClient(item.Message.Time, item.Message.Msgid, item.Nick, item.AccountName, nil, "NICK", item.Params[0])
			} else {
				message := fmt.Sprintf(client.t("%[1]s changed nick to %[2]s"), nick, item.Params[0])
				rb.AddFromClient(item.Message.Time, utils.MungeSecretToken(item.Message.Msgid), histServMask, "*", nil, "PRIVMSG", chname, message)
			}
		case history.Topic:
			if eventPlayback {
				rb.AddFromClient(item.Message.Time, item.Message.Msgid, item.Nick, item.AccountName, nil, "TOPIC", chname, item.Message.Message)
			} else {
				message := fmt.Sprintf(client.t("%[1]s set the channel topic to: %[2]s"), nick, item.Message.Message)
				rb.AddFromClient(item.Message.Time, utils.MungeSecretToken(item.Message.Msgid), histServMask, "*", nil, "PRIVMSG", chname, message)
			}
		case history.Mode:
			params := make([]string, len(item.Message.Split)+1)
			params[0] = chname
			for i, pair := range item.Message.Split {
				params[i+1] = pair.Message
			}
			if eventPlayback {
				rb.AddFromClient(item.Message.Time, item.Message.Msgid, item.Nick, item.AccountName, nil, "MODE", params...)
			} else {
				message := fmt.Sprintf(client.t("%[1]s set channel modes: %[2]s"), nick, strings.Join(params[1:], " "))
				rb.AddFromClient(item.Message.Time, utils.MungeSecretToken(item.Message.Msgid), histServMask, "*", nil, "PRIVMSG", chname, message)
			}
		}
	}
}

// SendTopic sends the channel topic to the given client.
// `sendNoTopic` controls whether RPL_NOTOPIC is sent when the topic is unset
func (channel *Channel) SendTopic(client *Client, rb *ResponseBuffer, sendNoTopic bool) {
	channel.stateMutex.RLock()
	name := channel.name
	topic := channel.topic
	topicSetBy := channel.topicSetBy
	topicSetTime := channel.topicSetTime
	_, hasClient := channel.members[client]
	channel.stateMutex.RUnlock()

	if !hasClient {
		rb.Add(nil, client.server.name, ERR_NOTONCHANNEL, client.Nick(), channel.name, client.t("You're not on that channel"))
		return
	}

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
		rb.Add(nil, client.server.name, ERR_NOTONCHANNEL, client.Nick(), channel.Name(), client.t("You're not on that channel"))
		return
	}

	if channel.flags.HasMode(modes.OpOnlyTopic) && !channel.ClientIsAtLeast(client, modes.ChannelOperator) {
		rb.Add(nil, client.server.name, ERR_CHANOPRIVSNEEDED, client.Nick(), channel.Name(), client.t("You're not a channel operator"))
		return
	}

	topicLimit := client.server.Config().Limits.TopicLen
	if len(topic) > topicLimit {
		topic = topic[:topicLimit]
	}

	channel.stateMutex.Lock()
	chname := channel.name
	channel.topic = topic
	channel.topicSetBy = client.nickMaskString
	channel.topicSetTime = time.Now().UTC()
	channel.stateMutex.Unlock()

	details := client.Details()
	message := utils.MakeMessage(topic)
	rb.AddFromClient(message.Time, message.Msgid, details.nickMask, details.accountName, nil, "TOPIC", chname, topic)
	for _, member := range channel.Members() {
		for _, session := range member.Sessions() {
			if session != rb.session {
				session.sendFromClientInternal(false, message.Time, message.Msgid, details.nickMask, details.accountName, nil, "TOPIC", chname, topic)
			}
		}
	}

	channel.AddHistoryItem(history.Item{
		Type:        history.Topic,
		Nick:        details.nickMask,
		AccountName: details.accountName,
		Message:     message,
	}, details.account)

	channel.MarkDirty(IncludeTopic)
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

func msgCommandToHistType(command string) (history.ItemType, error) {
	switch command {
	case "PRIVMSG":
		return history.Privmsg, nil
	case "NOTICE":
		return history.Notice, nil
	case "TAGMSG":
		return history.Tagmsg, nil
	default:
		return history.ItemType(0), errInvalidParams
	}
}

func (channel *Channel) SendSplitMessage(command string, minPrefixMode modes.Mode, clientOnlyTags map[string]string, client *Client, message utils.SplitMessage, rb *ResponseBuffer) {
	histType, err := msgCommandToHistType(command)
	if err != nil {
		return
	}

	if !channel.CanSpeak(client) {
		if histType != history.Notice {
			rb.Add(nil, client.server.name, ERR_CANNOTSENDTOCHAN, client.Nick(), channel.Name(), client.t("Cannot send to channel"))
		}
		return
	}

	isCTCP := message.IsRestrictedCTCPMessage()
	if isCTCP && channel.flags.HasMode(modes.NoCTCP) {
		if histType != history.Notice {
			rb.Add(nil, client.server.name, ERR_CANNOTSENDTOCHAN, client.Nick(), channel.Name(), fmt.Sprintf(client.t("Cannot send to channel (+%s)"), "C"))
		}
		return
	}

	details := client.Details()
	chname := channel.Name()

	// STATUSMSG targets are prefixed with the supplied min-prefix, e.g., @#channel
	if minPrefixMode != modes.Mode(0) {
		chname = fmt.Sprintf("%s%s", modes.ChannelModePrefixes[minPrefixMode], chname)
	}

	// send echo-message
	if rb.session.capabilities.Has(caps.EchoMessage) {
		var tagsToUse map[string]string
		if rb.session.capabilities.Has(caps.MessageTags) {
			tagsToUse = clientOnlyTags
		}
		if histType == history.Tagmsg && rb.session.capabilities.Has(caps.MessageTags) {
			rb.AddFromClient(message.Time, message.Msgid, details.nickMask, details.accountName, tagsToUse, command, chname)
		} else {
			rb.AddSplitMessageFromClient(details.nickMask, details.accountName, tagsToUse, command, chname, message)
		}
	}
	// send echo-message to other connected sessions
	for _, session := range client.Sessions() {
		if session == rb.session {
			continue
		}
		var tagsToUse map[string]string
		if session.capabilities.Has(caps.MessageTags) {
			tagsToUse = clientOnlyTags
		}
		if histType == history.Tagmsg && session.capabilities.Has(caps.MessageTags) {
			session.sendFromClientInternal(false, message.Time, message.Msgid, details.nickMask, details.accountName, tagsToUse, command, chname)
		} else if histType != history.Tagmsg {
			session.sendSplitMsgFromClientInternal(false, details.nickMask, details.accountName, tagsToUse, command, chname, message)
		}
	}

	for _, member := range channel.Members() {
		// echo-message is handled above, so skip sending the msg to the user themselves as well
		if member == client {
			continue
		}
		if minPrefixMode != modes.Mode(0) && !channel.ClientIsAtLeast(member, minPrefixMode) {
			// STATUSMSG
			continue
		}

		for _, session := range member.Sessions() {
			if isCTCP && session.isTor {
				continue // #753
			}

			var tagsToUse map[string]string
			if session.capabilities.Has(caps.MessageTags) {
				tagsToUse = clientOnlyTags
			} else if histType == history.Tagmsg {
				continue
			}

			if histType == history.Tagmsg {
				session.sendFromClientInternal(false, message.Time, message.Msgid, details.nickMask, details.accountName, tagsToUse, command, chname)
			} else {
				session.sendSplitMsgFromClientInternal(false, details.nickMask, details.accountName, tagsToUse, command, chname, message)
			}
		}
	}

	// #959: don't save STATUSMSG
	if minPrefixMode == modes.Mode(0) {
		channel.AddHistoryItem(history.Item{
			Type:        histType,
			Message:     message,
			Nick:        details.nickMask,
			AccountName: details.accountName,
			Tags:        clientOnlyTags,
		}, details.account)
	}
}

func (channel *Channel) applyModeToMember(client *Client, change modes.ModeChange, rb *ResponseBuffer) (applied bool, result modes.ModeChange) {
	target := channel.server.clients.Get(change.Arg)
	if target == nil {
		rb.Add(nil, client.server.name, ERR_NOSUCHNICK, client.Nick(), utils.SafeErrorParam(change.Arg), client.t("No such nick"))
		return
	}
	change.Arg = target.Nick()

	channel.stateMutex.Lock()
	modeset, exists := channel.members[target]
	if exists {
		if modeset.SetMode(change.Mode, change.Op == modes.Add) {
			applied = true
			result = change
		}
	}
	channel.stateMutex.Unlock()

	if !exists {
		rb.Add(nil, client.server.name, ERR_USERNOTINCHANNEL, client.Nick(), channel.Name(), client.t("They aren't on that channel"))
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
	chname := channel.Name()
	for mask, info := range channel.lists[mode].Masks() {
		rb.Add(nil, client.server.name, rpllist, nick, chname, mask, info.CreatorNickmask, strconv.FormatInt(info.TimeCreated.Unix(), 10))
	}

	rb.Add(nil, client.server.name, rplendoflist, nick, chname, client.t("End of list"))
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

func (channel *Channel) Kick(client *Client, target *Client, comment string, rb *ResponseBuffer, hasPrivs bool) {
	if !hasPrivs {
		if !(client.HasMode(modes.Operator) || channel.hasClient(client)) {
			rb.Add(nil, client.server.name, ERR_NOTONCHANNEL, client.Nick(), channel.Name(), client.t("You're not on that channel"))
			return
		}
		if !channel.ClientHasPrivsOver(client, target) {
			rb.Add(nil, client.server.name, ERR_CHANOPRIVSNEEDED, client.Nick(), channel.Name(), client.t("You don't have enough channel privileges"))
			return
		}
	}
	if !channel.hasClient(target) {
		rb.Add(nil, client.server.name, ERR_USERNOTINCHANNEL, client.Nick(), channel.Name(), client.t("They aren't on that channel"))
		return
	}

	kicklimit := channel.server.Config().Limits.KickLen
	if len(comment) > kicklimit {
		comment = comment[:kicklimit]
	}

	message := utils.MakeMessage(comment)
	details := client.Details()

	targetNick := target.Nick()
	chname := channel.Name()
	for _, member := range channel.Members() {
		for _, session := range member.Sessions() {
			if session != rb.session {
				session.sendFromClientInternal(false, message.Time, message.Msgid, details.nickMask, details.accountName, nil, "KICK", chname, targetNick, comment)
			}
		}
	}
	rb.AddFromClient(message.Time, message.Msgid, details.nickMask, details.accountName, nil, "KICK", chname, targetNick, comment)

	histItem := history.Item{
		Type:        history.Kick,
		Nick:        details.nickMask,
		AccountName: details.accountName,
		Message:     message,
	}
	histItem.Params[0] = targetNick
	channel.AddHistoryItem(histItem, details.account)

	channel.Quit(target)
}

// Invite invites the given client to the channel, if the inviter can do so.
func (channel *Channel) Invite(invitee *Client, inviter *Client, rb *ResponseBuffer) {
	chname := channel.Name()
	if channel.flags.HasMode(modes.InviteOnly) && !channel.ClientIsAtLeast(inviter, modes.ChannelOperator) {
		rb.Add(nil, inviter.server.name, ERR_CHANOPRIVSNEEDED, inviter.Nick(), chname, inviter.t("You're not a channel operator"))
		return
	}

	if !channel.hasClient(inviter) {
		rb.Add(nil, inviter.server.name, ERR_NOTONCHANNEL, inviter.Nick(), chname, inviter.t("You're not on that channel"))
		return
	}

	if channel.hasClient(invitee) {
		rb.Add(nil, inviter.server.name, ERR_USERONCHANNEL, inviter.Nick(), invitee.Nick(), chname, inviter.t("User is already on that channel"))
		return
	}

	invitee.Invite(channel.NameCasefolded())

	for _, member := range channel.Members() {
		if member == inviter || member == invitee || !channel.ClientIsAtLeast(member, modes.Halfop) {
			continue
		}
		for _, session := range member.Sessions() {
			if session.capabilities.Has(caps.InviteNotify) {
				session.Send(nil, inviter.NickMaskString(), "INVITE", invitee.Nick(), chname)
			}
		}
	}

	cnick := inviter.Nick()
	tnick := invitee.Nick()
	rb.Add(nil, inviter.server.name, RPL_INVITING, cnick, tnick, chname)
	invitee.Send(nil, inviter.NickMaskString(), "INVITE", tnick, chname)
	if invitee.Away() {
		rb.Add(nil, inviter.server.name, RPL_AWAY, cnick, tnick, invitee.AwayMessage())
	}
}

// data for RPL_LIST
func (channel *Channel) listData() (memberCount int, name, topic string) {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return len(channel.members), channel.name, channel.topic
}
