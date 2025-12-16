// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"sync"

	"github.com/ergochat/ergo/irc/caps"
	"github.com/ergochat/ergo/irc/utils"

	"github.com/ergochat/irc-go/ircmsg"
)

// MonitorManager keeps track of who's monitoring which nicks.
type MonitorManager struct {
	sync.RWMutex // tier 2
	// client -> (casefolded nick it's watching -> uncasefolded nick)
	watching map[*Session]map[string]string
	// casefolded nick -> clients watching it
	watchedby map[string]utils.HashSet[*Session]
}

func (mm *MonitorManager) Initialize() {
	mm.watching = make(map[*Session]map[string]string)
	mm.watchedby = make(map[string]utils.HashSet[*Session])
}

// AddMonitors adds clients using extended-monitor monitoring `client`'s nick to the passed user set.
func (manager *MonitorManager) AddMonitors(users utils.HashSet[*Session], cfnick string, capabs ...caps.Capability) {
	var requireExtendedMonitor bool
	for _, c := range capabs {
		// these are the four capabilities that explicitly require extended-monitor;
		// draft/metadata-2 does not
		if c == caps.AccountNotify || c == caps.AwayNotify || c == caps.ChgHost || c == caps.SetName {
			requireExtendedMonitor = true
			break
		}
	}

	manager.RLock()
	defer manager.RUnlock()
	for session := range manager.watchedby[cfnick] {
		if requireExtendedMonitor && !session.capabilities.Has(caps.ExtendedMonitor) {
			continue
		}
		if !session.capabilities.HasAll(capabs...) {
			continue
		}
		users.Add(session)
	}
}

// AlertAbout alerts everyone monitoring `client`'s nick that `client` is now {on,off}line.
func (manager *MonitorManager) AlertAbout(nick, cfnick string, online bool, client *Client) {
	var watchers []*Session
	// safely copy the list of clients watching our nick
	manager.RLock()
	for session := range manager.watchedby[cfnick] {
		watchers = append(watchers, session)
	}
	manager.RUnlock()

	command := RPL_MONOFFLINE
	if online {
		command = RPL_MONONLINE
	}

	var metadata map[string]string
	if online && client != nil {
		metadata = client.ListMetadata()
	}

	for _, session := range watchers {
		session.Send(nil, session.client.server.name, command, session.client.Nick(), nick)

		if metadata != nil && session.capabilities.Has(caps.Metadata) {
			for key := range session.MetadataSubscriptions() {
				if val, ok := metadata[key]; ok {
					session.Send(nil, client.server.name, "METADATA", nick, key, "*", val)
				}
			}
		}
	}
}

// Add registers `client` to receive notifications about `nick`.
func (manager *MonitorManager) Add(session *Session, nick string, limit int) error {
	cfnick, err := CasefoldName(nick)
	if err != nil {
		return err
	}

	manager.Lock()
	defer manager.Unlock()

	if manager.watching[session] == nil {
		manager.watching[session] = make(map[string]string)
	}
	if manager.watchedby[cfnick] == nil {
		manager.watchedby[cfnick] = make(utils.HashSet[*Session])
	}

	if len(manager.watching[session]) >= limit {
		return errMonitorLimitExceeded
	}

	manager.watching[session][cfnick] = nick
	manager.watchedby[cfnick].Add(session)
	return nil
}

// Remove unregisters `client` from receiving notifications about `nick`.
func (manager *MonitorManager) Remove(session *Session, nick string) (err error) {
	cfnick, err := CasefoldName(nick)
	if err != nil {
		return
	}

	manager.Lock()
	defer manager.Unlock()
	delete(manager.watching[session], cfnick)
	manager.watchedby[cfnick].Remove(session)
	return nil
}

// RemoveAll unregisters `client` from receiving notifications about *all* nicks.
func (manager *MonitorManager) RemoveAll(session *Session) {
	manager.Lock()
	defer manager.Unlock()

	for cfnick := range manager.watching[session] {
		manager.watchedby[cfnick].Remove(session)
	}
	delete(manager.watching, session)
}

// List lists all nicks that `client` is registered to receive notifications about.
func (manager *MonitorManager) List(session *Session) (nicks []string) {
	manager.RLock()
	defer manager.RUnlock()
	for _, nick := range manager.watching[session] {
		nicks = append(nicks, nick)
	}
	return nicks
}

var (
	monitorSubcommands = map[string]func(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool{
		"-": monitorRemoveHandler,
		"+": monitorAddHandler,
		"c": monitorClearHandler,
		"l": monitorListHandler,
		"s": monitorStatusHandler,
	}
)
