// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/goshuirc/irc-go/ircmsg"
)

type MonitorManager struct {
	sync.RWMutex
	// client -> nicks it's watching
	watching map[*Client]map[string]bool
	// nick -> clients watching it
	watchedby map[string]map[*Client]bool
	// (all nicks must be normalized externally by casefolding)
}

func NewMonitorManager() *MonitorManager {
	mm := MonitorManager{
		watching:  make(map[*Client]map[string]bool),
		watchedby: make(map[string]map[*Client]bool),
	}
	return &mm
}

var MonitorLimitExceeded = errors.New("Monitor limit exceeded")

// alertMonitors alerts everyone monitoring us that we're online.
func (manager *MonitorManager) alertMonitors(client *Client, online bool) {
	cfnick := client.getNickCasefolded()
	nick := client.getNick()
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

	// asynchronously send all the notifications
	go func() {
		for _, mClient := range watchers {
			// don't have to notify ourselves
			if mClient != client {
				mClient.SendFromClient("", client, nil, command, mClient.getNick(), nick)
			}
		}
	}()
}

// clearMonitorList clears our MONITOR list.
func (manager *MonitorManager) clearMonitorList(client *Client) {
	manager.Lock()
	defer manager.Unlock()

	for nick, _ := range manager.watching[client] {
		delete(manager.watchedby[nick], client)
	}
	delete(manager.watching, client)
}

func (manager *MonitorManager) addMonitor(client *Client, nick string, limit int) error {
	manager.Lock()
	defer manager.Unlock()

	if manager.watching[client] == nil {
		manager.watching[client] = make(map[string]bool)
	}
	if manager.watchedby[nick] == nil {
		manager.watchedby[nick] = make(map[*Client]bool)
	}

	if len(manager.watching[client]) >= limit {
		return MonitorLimitExceeded
	}

	manager.watching[client][nick] = true
	manager.watchedby[nick][client] = true
	return nil
}

func (manager *MonitorManager) removeMonitor(client *Client, nick string) error {
	manager.Lock()
	defer manager.Unlock()
	// deleting from nil maps is fine
	delete(manager.watching[client], nick)
	delete(manager.watchedby[nick], client)
	return nil
}

func (manager *MonitorManager) listMonitors(client *Client) (nicks []string) {
	manager.RLock()
	defer manager.RUnlock()
	for nick := range manager.watching[client] {
		nicks = append(nicks, nick)
	}
	return nicks
}

var (
	metadataSubcommands = map[string]func(server *Server, client *Client, msg ircmsg.IrcMessage) bool{
		"-": monitorRemoveHandler,
		"+": monitorAddHandler,
		"c": monitorClearHandler,
		"l": monitorListHandler,
		"s": monitorStatusHandler,
	}
)

func monitorHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	handler, exists := metadataSubcommands[strings.ToLower(msg.Params[0])]

	if !exists {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.getNick(), "MONITOR", msg.Params[0], "Unknown subcommand")
		return false
	}

	return handler(server, client, msg)
}

func monitorRemoveHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if len(msg.Params) < 2 {
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.getNick(), msg.Command, "Not enough parameters")
		return false
	}

	targets := strings.Split(msg.Params[1], ",")
	for _, target := range targets {
		cfnick, err := CasefoldName(target)
		if err != nil {
			continue
		}
		server.monitorManager.removeMonitor(client, cfnick)
	}

	return false
}

func monitorAddHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if len(msg.Params) < 2 {
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.getNick(), msg.Command, "Not enough parameters")
		return false
	}

	var online []string
	var offline []string

	limit := server.getLimits().MonitorEntries

	targets := strings.Split(msg.Params[1], ",")
	for _, target := range targets {
		// check name length
		if len(target) < 1 || len(targets) > server.limits.NickLen {
			continue
		}

		// add target
		casefoldedTarget, err := CasefoldName(targets[0])
		if err != nil {
			continue
		}

		err = server.monitorManager.addMonitor(client, casefoldedTarget, limit)
		if err == MonitorLimitExceeded {
			client.Send(nil, server.name, ERR_MONLISTFULL, client.getNick(), strconv.Itoa(server.limits.MonitorEntries), strings.Join(targets, ","))
			break
		} else if err != nil {
			continue
		}

		// add to online / offline lists
		if target := server.clients.Get(casefoldedTarget); target == nil {
			offline = append(offline, targets[0])
		} else {
			online = append(online, target.getNick())
		}
	}

	if len(online) > 0 {
		client.Send(nil, server.name, RPL_MONONLINE, client.getNick(), strings.Join(online, ","))
	}
	if len(offline) > 0 {
		client.Send(nil, server.name, RPL_MONOFFLINE, client.getNick(), strings.Join(offline, ","))
	}

	return false
}

func monitorClearHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	server.monitorManager.clearMonitorList(client)
	return false
}

func monitorListHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	monitorList := server.monitorManager.listMonitors(client)

	for _, line := range argsToStrings(maxLastArgLength, monitorList, ",") {
		client.Send(nil, server.name, RPL_MONLIST, client.getNick(), line)
	}

	client.Send(nil, server.name, RPL_ENDOFMONLIST, "End of MONITOR list")

	return false
}

func monitorStatusHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var online []string
	var offline []string

	monitorList := server.monitorManager.listMonitors(client)

	for _, name := range monitorList {
		target := server.clients.Get(name)
		if target == nil {
			offline = append(offline, name)
		} else {
			online = append(online, target.getNick())
		}
	}

	if len(online) > 0 {
		for _, line := range argsToStrings(maxLastArgLength, online, ",") {
			client.Send(nil, server.name, RPL_MONONLINE, client.getNick(), line)
		}
	}
	if len(offline) > 0 {
		for _, line := range argsToStrings(maxLastArgLength, offline, ",") {
			client.Send(nil, server.name, RPL_MONOFFLINE, client.getNick(), line)
		}
	}

	return false
}
