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
	// client -> nicks it's watching
	watching map[*Client]map[string]bool
	// nick -> clients watching it
	watchedby map[string]map[*Client]bool
	// (all nicks must be normalized externally by casefolding)
}

func (mm *MonitorManager) Initialize() {
	mm.watching = make(map[*Client]map[string]bool)
	mm.watchedby = make(map[string]map[*Client]bool)
}

// AlertAbout alerts everyone monitoring `client`'s nick that `client` is now {on,off}line.
func (manager *MonitorManager) AlertAbout(client *Client, online bool) {
	cfnick := client.NickCasefolded()
	nick := client.Nick()
	var watchers []*Client
	// safely copy the list of clients watching our nick
	manager.RLock()
	for client := range manager.watchedby[cfnick] {
		watchers = append(watchers, client)
	}
	manager.RUnlock()

	command := RPL_MONOFFLINE
	if online {
		command = RPL_MONONLINE
	}

	for _, mClient := range watchers {
		mClient.Send(nil, client.server.name, command, mClient.Nick(), nick)
	}
}

// Add registers `client` to receive notifications about `nick`.
func (manager *MonitorManager) Add(client *Client, nick string, limit int) error {
	manager.Lock()
	defer manager.Unlock()

	if manager.watching[client] == nil {
		manager.watching[client] = make(map[string]bool)
	}
	if manager.watchedby[nick] == nil {
		manager.watchedby[nick] = make(map[*Client]bool)
	}

	if len(manager.watching[client]) >= limit {
		return errMonitorLimitExceeded
	}

	manager.watching[client][nick] = true
	manager.watchedby[nick][client] = true
	return nil
}

// Remove unregisters `client` from receiving notifications about `nick`.
func (manager *MonitorManager) Remove(client *Client, nick string) error {
	manager.Lock()
	defer manager.Unlock()
	// deleting from nil maps is fine
	delete(manager.watching[client], nick)
	delete(manager.watchedby[nick], client)
	return nil
}

// RemoveAll unregisters `client` from receiving notifications about *all* nicks.
func (manager *MonitorManager) RemoveAll(client *Client) {
	manager.Lock()
	defer manager.Unlock()

	for nick := range manager.watching[client] {
		delete(manager.watchedby[nick], client)
	}
	delete(manager.watching, client)
}

// List lists all nicks that `client` is registered to receive notifications about.
func (manager *MonitorManager) List(client *Client) (nicks []string) {
	manager.RLock()
	defer manager.RUnlock()
	for nick := range manager.watching[client] {
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
