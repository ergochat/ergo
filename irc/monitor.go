// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"sync"

	"github.com/goshuirc/irc-go/ircmsg"
)

// MonitorManager keeps track of who's monitoring which nicks.
type MonitorManager struct {
	sync.RWMutex // tier 2
	// client -> (casefolded nick it's watching -> uncasefolded nick)
	watching map[*Session]map[string]string
	// casefolded nick -> clients watching it
	watchedby map[string]map[*Session]empty
}

func (mm *MonitorManager) Initialize() {
	mm.watching = make(map[*Session]map[string]string)
	mm.watchedby = make(map[string]map[*Session]empty)
}

// AlertAbout alerts everyone monitoring `client`'s nick that `client` is now {on,off}line.
func (manager *MonitorManager) AlertAbout(nick, cfnick string, online bool) {
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

	for _, session := range watchers {
		session.Send(nil, session.client.server.name, command, session.client.Nick(), nick)
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
		manager.watchedby[cfnick] = make(map[*Session]empty)
	}

	if len(manager.watching[session]) >= limit {
		return errMonitorLimitExceeded
	}

	manager.watching[session][cfnick] = nick
	manager.watchedby[cfnick][session] = empty{}
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
	delete(manager.watchedby[cfnick], session)
	return nil
}

// RemoveAll unregisters `client` from receiving notifications about *all* nicks.
func (manager *MonitorManager) RemoveAll(session *Session) {
	manager.Lock()
	defer manager.Unlock()

	for cfnick := range manager.watching[session] {
		delete(manager.watchedby[cfnick], session)
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
	monitorSubcommands = map[string]func(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool{
		"-": monitorRemoveHandler,
		"+": monitorAddHandler,
		"c": monitorClearHandler,
		"l": monitorListHandler,
		"s": monitorStatusHandler,
	}
)
