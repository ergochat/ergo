// Copyright (c) 2017 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"fmt"
	"maps"
	"net"
	"time"

	"github.com/ergochat/ergo/irc/caps"
	"github.com/ergochat/ergo/irc/languages"
	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/utils"
	"github.com/ergochat/ergo/irc/webpush"
)

func (server *Server) Config() (config *Config) {
	return server.config.Load()
}

func (server *Server) GetOperator(name string) (oper *Oper) {
	name, err := CasefoldName(name)
	if err != nil {
		return
	}
	return server.Config().operators[name]
}

func (server *Server) Languages() (lm *languages.Manager) {
	return server.Config().languageManager
}

func (server *Server) Defcon() uint32 {
	return server.defcon.Load()
}

func (server *Server) SetDefcon(defcon uint32) {
	server.defcon.Store(defcon)
}

func (client *Client) Sessions() (sessions []*Session) {
	client.stateMutex.RLock()
	sessions = client.sessions
	client.stateMutex.RUnlock()
	return
}

type SessionData struct {
	ctime     time.Time
	atime     time.Time
	ip        net.IP
	hostname  string
	certfp    string
	deviceID  string
	connInfo  string
	connID    string
	sessionID int64
	caps      []string
}

func (client *Client) AllSessionData(currentSession *Session, hasPrivs bool) (data []SessionData, currentIndex int) {
	currentIndex = -1
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()

	data = make([]SessionData, len(client.sessions))
	for i, session := range client.sessions {
		if session == currentSession {
			currentIndex = i
		}
		data[i] = SessionData{
			atime:     session.lastActive,
			ctime:     session.ctime,
			hostname:  session.rawHostname,
			certfp:    session.certfp,
			deviceID:  session.deviceID,
			connID:    session.connID,
			sessionID: session.sessionID,
		}
		if session.proxiedIP != nil {
			data[i].ip = session.proxiedIP
		} else {
			data[i].ip = session.realIP
		}
		if hasPrivs {
			data[i].connInfo = utils.DescribeConn(session.socket.conn.UnderlyingConn().Conn)
		}
		data[i].caps = session.capabilities.Strings(caps.Cap302, nil, 300)
	}
	return
}

func (client *Client) AddSession(session *Session) (success bool, numSessions int, lastSeen time.Time, wasAway, nowAway string) {
	config := client.server.Config()
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	// client may be dying and ineligible to receive another session
	if client.destroyed {
		return
	}
	// success, attach the new session to the client
	session.client = client
	session.sessionID = client.nextSessionID
	client.nextSessionID++
	newSessions := make([]*Session, len(client.sessions)+1)
	copy(newSessions, client.sessions)
	newSessions[len(newSessions)-1] = session
	if client.accountSettings.AutoreplayMissed || session.deviceID != "" {
		lastSeen = client.lastSeen[session.deviceID]
		client.setLastSeen(time.Now().UTC(), session.deviceID)
	}
	client.sessions = newSessions
	wasAway = client.awayMessage
	if client.autoAwayEnabledNoMutex(config) {
		client.setAutoAwayNoMutex(config)
	} else {
		if session.awayMessage != "" && session.awayMessage != "*" {
			// set the away message
			client.awayMessage = session.awayMessage
		} else if session.awayMessage == "" && !session.awayAt.IsZero() {
			// weird edge case: explicit `AWAY` or `AWAY :` during pre-registration makes the client back
			client.awayMessage = ""
		}
		// else: the client sent no AWAY command at all, no-op
		// or: the client sent `AWAY *`, which should not modify the publicly visible away state
	}
	nowAway = client.awayMessage
	return true, len(client.sessions), lastSeen, wasAway, nowAway
}

func (client *Client) removeSession(session *Session) (success bool, length int) {
	if len(client.sessions) == 0 {
		return
	}
	sessions := make([]*Session, 0, len(client.sessions)-1)
	for _, currentSession := range client.sessions {
		if session == currentSession {
			success = true
		} else {
			sessions = append(sessions, currentSession)
		}
	}
	client.sessions = sessions
	length = len(sessions)
	return
}

// #1650: show an arbitrarily chosen session IP and hostname in RPL_WHOISACTUALLY
func (client *Client) getWhoisActually() (ip net.IP, hostname string) {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()

	for _, session := range client.sessions {
		return session.IP(), session.rawHostname
	}
	return utils.IPv4LoopbackAddress, client.server.name
}

func (client *Client) Nick() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.nick
}

func (client *Client) NickMaskString() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.nickMaskString
}

func (client *Client) NickCasefolded() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.nickCasefolded
}

func (client *Client) NickMaskCasefolded() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.nickMaskCasefolded
}

func (client *Client) Username() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.username
}

func (client *Client) Hostname() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.hostname
}

func (client *Client) Away() (result bool, message string) {
	client.stateMutex.Lock()
	message = client.awayMessage
	client.stateMutex.Unlock()
	result = client.awayMessage != ""
	return
}

func (session *Session) SetAway(awayMessage string) (wasAway, nowAway string) {
	client := session.client
	config := client.server.Config()

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	session.awayMessage = awayMessage
	session.awayAt = time.Now().UTC()

	wasAway = client.awayMessage
	if client.autoAwayEnabledNoMutex(config) {
		client.setAutoAwayNoMutex(config)
	} else if awayMessage != "*" {
		client.awayMessage = awayMessage
	} // else: `AWAY *`, should not modify publicly visible away state
	nowAway = client.awayMessage
	return
}

func (session *Session) ConnID() string {
	if session == nil {
		return "*"
	}
	return session.connID
}

func (client *Client) autoAwayEnabledNoMutex(config *Config) bool {
	return client.registered && client.alwaysOn &&
		persistenceEnabled(config.Accounts.Multiclient.AutoAway, client.accountSettings.AutoAway)
}

func (client *Client) setAutoAwayNoMutex(config *Config) {
	// aggregate the away statuses of the individual sessions:
	var globalAwayState string
	var awaySetAt time.Time
	for _, cSession := range client.sessions {
		if cSession.awayMessage == "" {
			// a session is active, we are not auto-away
			client.awayMessage = ""
			return
		} else if cSession.awayAt.After(awaySetAt) && cSession.awayMessage != "*" {
			// choose the latest valid away message from any session
			globalAwayState = cSession.awayMessage
			awaySetAt = cSession.awayAt
		}
	}
	if awaySetAt.IsZero() {
		// no sessions, enable auto-away
		client.awayMessage = config.languageManager.Translate(client.languages, `User is currently disconnected`)
	} else {
		client.awayMessage = globalAwayState
	}
}

func (client *Client) AlwaysOn() (alwaysOn bool) {
	client.stateMutex.RLock()
	alwaysOn = client.registered && client.alwaysOn
	client.stateMutex.RUnlock()
	return
}

// uniqueIdentifiers returns the strings for which the server enforces per-client
// uniqueness/ownership; no two clients can have colliding casefolded nicks or
// skeletons.
func (client *Client) uniqueIdentifiers() (nickCasefolded string, skeleton string) {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.nickCasefolded, client.skeleton
}

func (client *Client) Oper() *Oper {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.oper
}

func (client *Client) Registered() (result bool) {
	// `registered` is only written from the client's own goroutine, but may be
	// read from other goroutines; therefore, the client's own goroutine may read
	// the value without synchronization, but must write it with synchronization,
	// and other goroutines must read it with synchronization
	client.stateMutex.RLock()
	result = client.registered
	client.stateMutex.RUnlock()
	return
}

func (client *Client) RawHostname() (result string) {
	client.stateMutex.Lock()
	result = client.rawHostname
	client.stateMutex.Unlock()
	return
}

func (client *Client) AwayMessage() (result string) {
	client.stateMutex.RLock()
	result = client.awayMessage
	client.stateMutex.RUnlock()
	return
}

func (client *Client) Account() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.account
}

func (client *Client) AccountName() string {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.accountName
}

func (client *Client) Login(account ClientAccount) {
	alwaysOn := persistenceEnabled(client.server.Config().Accounts.Multiclient.AlwaysOn, account.Settings.AlwaysOn)
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	client.account = account.NameCasefolded
	client.accountName = account.Name
	client.accountSettings = account.Settings
	// mark always-on here: it will not be respected until the client is registered
	client.alwaysOn = alwaysOn
	client.accountRegDate = account.RegisteredAt
	return
}

func (client *Client) setAccountName(name string) {
	// XXX this assumes validation elsewhere
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	client.accountName = name
}

func (client *Client) setCloakedHostname(cloak string) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	client.cloakedHostname = cloak
	client.updateNickMaskNoMutex()
}

func (client *Client) CloakedHostname() string {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	return client.cloakedHostname
}

func (client *Client) historyCutoff() (cutoff time.Time) {
	client.stateMutex.Lock()
	if client.account != "" {
		cutoff = client.accountRegDate
	} else {
		cutoff = client.ctime
	}
	client.stateMutex.Unlock()
	return
}

func (client *Client) Logout() {
	client.stateMutex.Lock()
	client.account = ""
	client.accountName = "*"
	client.alwaysOn = false
	client.accountRegDate = time.Time{}
	client.accountSettings = AccountSettings{}
	client.stateMutex.Unlock()
}

func (client *Client) AccountSettings() (result AccountSettings) {
	client.stateMutex.RLock()
	result = client.accountSettings
	client.stateMutex.RUnlock()
	return
}

func (client *Client) SetAccountSettings(settings AccountSettings) {
	// we mark dirty if the client is transitioning to always-on
	var becameAlwaysOn bool
	alwaysOn := persistenceEnabled(client.server.Config().Accounts.Multiclient.AlwaysOn, settings.AlwaysOn)
	client.stateMutex.Lock()
	if client.registered {
		// only allow the client to become always-on if their nick equals their account name
		alwaysOn = alwaysOn && client.nick == client.accountName
		becameAlwaysOn = (!client.alwaysOn && alwaysOn)
		client.alwaysOn = alwaysOn
	}
	client.accountSettings = settings
	client.stateMutex.Unlock()
	if becameAlwaysOn {
		client.markDirty(IncludeAllAttrs)
	}
}

func (client *Client) Languages() (languages []string) {
	client.stateMutex.RLock()
	languages = client.languages
	client.stateMutex.RUnlock()
	return languages
}

func (client *Client) SetLanguages(languages []string) {
	client.stateMutex.Lock()
	client.languages = languages
	client.stateMutex.Unlock()
}

func (client *Client) HasMode(mode modes.Mode) bool {
	// client.flags has its own synch
	return client.modes.HasMode(mode)
}

func (client *Client) SetMode(mode modes.Mode, on bool) bool {
	return client.modes.SetMode(mode, on)
}

func (client *Client) SetRealname(realname string) {
	client.stateMutex.Lock()
	client.realname = realname
	alwaysOn := client.registered && client.alwaysOn
	client.stateMutex.Unlock()
	if alwaysOn {
		client.markDirty(IncludeRealname)
	}
}

func (client *Client) Channels() (result []*Channel) {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	length := len(client.channels)
	result = make([]*Channel, length)
	i := 0
	for channel := range client.channels {
		result[i] = channel
		i++
	}
	return
}

func (client *Client) NumChannels() int {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return len(client.channels)
}

func (client *Client) WhoWas() (result WhoWas) {
	return client.Details().WhoWas
}

func (client *Client) Details() (result ClientDetails) {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.detailsNoMutex()
}

func (client *Client) detailsNoMutex() (result ClientDetails) {
	result.nick = client.nick
	result.nickCasefolded = client.nickCasefolded
	result.username = client.username
	result.hostname = client.hostname
	result.realname = client.realname
	result.ip = client.getIPNoMutex()
	result.nickMask = client.nickMaskString
	result.nickMaskCasefolded = client.nickMaskCasefolded
	result.account = client.account
	result.accountName = client.accountName
	return
}

func (client *Client) UpdateActive(session *Session) {
	now := time.Now().UTC()
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	client.lastActive = now
	session.lastActive = now
}

func (client *Client) Realname() string {
	client.stateMutex.RLock()
	result := client.realname
	client.stateMutex.RUnlock()
	return result
}

func (client *Client) IsExpiredAlwaysOn(config *Config) (result bool) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	return client.checkAlwaysOnExpirationNoMutex(config, false)
}

func (client *Client) checkAlwaysOnExpirationNoMutex(config *Config, ignoreRegistration bool) (result bool) {
	if !((client.registered || ignoreRegistration) && client.alwaysOn) {
		return false
	}
	deadline := time.Duration(config.Accounts.Multiclient.AlwaysOnExpiration)
	if deadline == 0 {
		return false
	}
	now := time.Now()
	for _, ts := range client.lastSeen {
		if now.Sub(ts) < deadline {
			return false
		}
	}
	return true
}

func (client *Client) GetReadMarker(cfname string) (result string) {
	client.stateMutex.RLock()
	t, ok := client.readMarkers[cfname]
	client.stateMutex.RUnlock()
	if ok {
		return fmt.Sprintf("timestamp=%s", t.Format(IRCv3TimestampFormat))
	}
	return "*"
}

func (client *Client) getMarkreadTime(cfname string) (timestamp time.Time, ok bool) {
	client.stateMutex.RLock()
	timestamp, ok = client.readMarkers[cfname]
	client.stateMutex.RUnlock()
	return
}

func (client *Client) copyReadMarkers() (result map[string]time.Time) {
	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return maps.Clone(client.readMarkers)
}

func (client *Client) SetReadMarker(cfname string, now time.Time) (result time.Time) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	if client.readMarkers == nil {
		client.readMarkers = make(map[string]time.Time)
	}
	result = updateLRUMap(client.readMarkers, cfname, now, maxReadMarkers)
	client.dirtyTimestamps = true
	return
}

func updateLRUMap(lru map[string]time.Time, key string, val time.Time, maxItems int) (result time.Time) {
	if currentVal := lru[key]; currentVal.After(val) {
		return currentVal
	}

	lru[key] = val
	// evict the least-recently-used entry if necessary
	if maxItems < len(lru) {
		var minKey string
		var minVal time.Time
		for key, val := range lru {
			if minVal.IsZero() || val.Before(minVal) {
				minKey, minVal = key, val
			}
		}
		delete(lru, minKey)
	}
	return val
}

func (client *Client) addClearablePushMessage(cftarget string, messageTime time.Time) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	if client.clearablePushMessages == nil {
		client.clearablePushMessages = make(map[string]time.Time)
	}
	updateLRUMap(client.clearablePushMessages, cftarget, messageTime, maxReadMarkers)
}

func (client *Client) clearClearablePushMessage(cftarget string, readTimestamp time.Time) (ok bool) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	pushMessageTime, ok := client.clearablePushMessages[cftarget]
	if ok && utils.ReadMarkerLessThanOrEqual(pushMessageTime, readTimestamp) {
		delete(client.clearablePushMessages, cftarget)
		return true
	}
	return false
}

func (client *Client) shouldFlushTimestamps() (result bool) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	result = client.dirtyTimestamps && client.registered && client.alwaysOn
	client.dirtyTimestamps = false
	return
}

func (client *Client) setKlined() {
	client.stateMutex.Lock()
	client.isKlined = true
	client.stateMutex.Unlock()
}

func (client *Client) refreshPushSubscription(endpoint string, keys webpush.Keys) bool {
	// do not mark dirty --- defer the write to periodic maintenance
	now := time.Now().UTC()

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	sub, ok := client.pushSubscriptions[endpoint]
	if ok && sub.Keys.Equal(keys) {
		sub.LastRefresh = now
		return true
	}
	return false // subscription doesn't exist, we need to send a test message
}

func (client *Client) addPushSubscription(endpoint string, keys webpush.Keys) error {
	changed := false

	defer func() {
		if changed {
			client.markDirty(IncludeAllAttrs)
		}
	}()

	config := client.server.Config()
	now := time.Now().UTC()

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	if client.pushSubscriptions == nil {
		client.pushSubscriptions = make(map[string]*pushSubscription)
	}

	sub, ok := client.pushSubscriptions[endpoint]
	if ok {
		changed = !sub.Keys.Equal(keys)
		sub.Keys = keys
		sub.LastRefresh = now
	} else {
		if len(client.pushSubscriptions) >= config.WebPush.MaxSubscriptions {
			return errLimitExceeded
		}
		changed = true
		sub = newPushSubscription(storedPushSubscription{
			Endpoint:    endpoint,
			Keys:        keys,
			LastRefresh: now,
			LastSuccess: now, // assume we just sent a successful message to confirm the sub
		})
		client.pushSubscriptions[endpoint] = sub
	}

	if changed {
		client.rebuildPushSubscriptionCache()
	}

	return nil
}

func (client *Client) hasPushSubscriptions() bool {
	return client.pushSubscriptionsExist.Load() != 0
}

func (client *Client) getPushSubscriptions(refresh bool) []storedPushSubscription {
	if refresh {
		func() {
			client.stateMutex.Lock()
			defer client.stateMutex.Unlock()
			client.rebuildPushSubscriptionCache()
		}()
	}

	client.stateMutex.RLock()
	defer client.stateMutex.RUnlock()
	return client.cachedPushSubscriptions
}

func (client *Client) rebuildPushSubscriptionCache() {
	// must hold write lock
	if len(client.pushSubscriptions) == 0 {
		client.cachedPushSubscriptions = nil
		client.pushSubscriptionsExist.Store(0)
		return
	}

	client.cachedPushSubscriptions = make([]storedPushSubscription, 0, len(client.pushSubscriptions))
	for _, subscription := range client.pushSubscriptions {
		client.cachedPushSubscriptions = append(client.cachedPushSubscriptions, subscription.storedPushSubscription)
	}
	client.pushSubscriptionsExist.Store(1)
}

func (client *Client) deletePushSubscription(endpoint string, writeback bool) (changed bool) {
	defer func() {
		if writeback && changed {
			client.markDirty(IncludeAllAttrs)
		}
	}()

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	_, ok := client.pushSubscriptions[endpoint]
	if ok {
		changed = true
		delete(client.pushSubscriptions, endpoint)
		client.rebuildPushSubscriptionCache()
	}
	return
}

func (client *Client) recordPush(endpoint string, success bool) {
	now := time.Now().UTC()

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()

	subscription, ok := client.pushSubscriptions[endpoint]
	if !ok {
		return
	}
	if success {
		subscription.LastSuccess = now
	}
	// TODO we may want to track failures in some way in the future
}

func (channel *Channel) Name() string {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.name
}

func (channel *Channel) NameCasefolded() string {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.nameCasefolded
}

func (channel *Channel) Rename(name, nameCasefolded string) {
	channel.stateMutex.Lock()
	channel.name = name
	if channel.nameCasefolded != nameCasefolded {
		channel.nameCasefolded = nameCasefolded
		if channel.registeredFounder != "" {
			channel.registeredTime = time.Now().UTC()
		}
	}
	channel.stateMutex.Unlock()
}

func (channel *Channel) Members() (result []*Client) {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.membersCache
}

func (channel *Channel) setUserLimit(limit int) {
	channel.stateMutex.Lock()
	channel.userLimit = limit
	channel.stateMutex.Unlock()
}

func (channel *Channel) setKey(key string) {
	channel.stateMutex.Lock()
	defer channel.stateMutex.Unlock()
	channel.key = key
}

func (channel *Channel) Founder() string {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.registeredFounder
}

func (channel *Channel) HighestUserMode(client *Client) (result modes.Mode) {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	if clientData, ok := channel.members[client]; ok {
		return clientData.modes.HighestChannelUserMode()
	}
	return
}

func (channel *Channel) Settings() (result ChannelSettings) {
	channel.stateMutex.RLock()
	result = channel.settings
	channel.stateMutex.RUnlock()
	return result
}

func (channel *Channel) SetSettings(settings ChannelSettings) {
	channel.stateMutex.Lock()
	channel.settings = settings
	channel.stateMutex.Unlock()
	channel.MarkDirty(IncludeSettings)
}

func (channel *Channel) setForward(forward string) {
	channel.stateMutex.Lock()
	channel.forward = forward
	channel.stateMutex.Unlock()
}

func (channel *Channel) Ctime() (ctime time.Time) {
	channel.stateMutex.RLock()
	ctime = channel.createdTime
	channel.stateMutex.RUnlock()
	return
}

func (channel *Channel) getAmode(cfaccount string) (result modes.Mode) {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.accountToUMode[cfaccount]
}

func (channel *Channel) UUID() utils.UUID {
	channel.stateMutex.RLock()
	defer channel.stateMutex.RUnlock()
	return channel.uuid
}
