// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"strconv"
	"strings"

	"github.com/DanielOaks/girc-go/ircmsg"
)

// alertMonitors alerts everyone monitoring us that we're online.
func (client *Client) alertMonitors() {
	// alert monitors
	for _, mClient := range client.server.monitoring[client.nickCasefolded] {
		// don't have to notify ourselves
		if &mClient != client {
			mClient.SendFromClient("", client, nil, RPL_MONONLINE, mClient.nick, client.nickMaskString)
		}
	}
}

// clearMonitorList clears our MONITOR list.
func (client *Client) clearMonitorList() {
	for name := range client.monitoring {
		// just removes current client from the list
		orig := client.server.monitoring[name]
		var index int
		for i, cli := range orig {
			if &cli == client {
				index = i
				break
			}
		}
		client.server.monitoring[name] = append(orig[:index], orig[index+1:]...)
	}

	client.monitoring = make(map[string]bool)
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
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, "MONITOR", msg.Params[0], "Unknown subcommand")
		return false
	}

	return handler(server, client, msg)
}

func monitorRemoveHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if len(msg.Params) < 2 {
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, msg.Command, "Not enough parameters")
		return false
	}

	targets := strings.Split(msg.Params[1], ",")
	for len(targets) > 0 {
		// check name length
		if len(targets[0]) < 1 {
			targets = targets[1:]
			continue
		}

		// remove target
		casefoldedTarget, err := CasefoldName(targets[0])
		if err != nil {
			// skip silently I guess
			targets = targets[1:]
			continue
		}

		if client.monitoring[casefoldedTarget] {
			// just removes current client from the list
			orig := server.monitoring[casefoldedTarget]
			var index int
			for i, cli := range orig {
				if &cli == client {
					index = i
					break
				}
			}
			server.monitoring[casefoldedTarget] = append(orig[:index], orig[index+1:]...)

			delete(client.monitoring, casefoldedTarget)
		}

		// remove first element of targets list
		targets = targets[1:]
	}

	return false
}

func monitorAddHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if len(msg.Params) < 2 {
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, msg.Command, "Not enough parameters")
		return false
	}

	var online []string
	var offline []string

	targets := strings.Split(msg.Params[1], ",")
	for len(targets) > 0 {
		// check name length
		if len(targets[0]) < 1 || len(targets[0]) > server.limits.NickLen {
			targets = targets[1:]
			continue
		}

		// check the monitor list length
		if len(client.monitoring) >= server.limits.MonitorEntries {
			client.Send(nil, server.name, ERR_MONLISTFULL, client.nick, strconv.Itoa(server.limits.MonitorEntries), strings.Join(targets, ","))
			break
		}

		// add target
		casefoldedTarget, err := CasefoldName(targets[0])
		if err != nil {
			// skip silently I guess
			targets = targets[1:]
			continue
		}

		if !client.monitoring[casefoldedTarget] {
			client.monitoring[casefoldedTarget] = true

			orig := server.monitoring[casefoldedTarget]
			server.monitoring[casefoldedTarget] = append(orig, *client)
		}

		// add to online / offline lists
		target := server.clients.Get(casefoldedTarget)
		if target == nil {
			offline = append(offline, targets[0])
		} else {
			online = append(online, target.nickMaskString)
		}

		// remove first element of targets list
		targets = targets[1:]
	}

	if len(online) > 0 {
		client.Send(nil, server.name, RPL_MONONLINE, client.nick, strings.Join(online, ","))
	}
	if len(offline) > 0 {
		client.Send(nil, server.name, RPL_MONOFFLINE, client.nick, strings.Join(offline, ","))
	}

	return false
}

func monitorClearHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	client.clearMonitorList()

	return false
}

func monitorListHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var monitorList []string
	for name := range client.monitoring {
		monitorList = append(monitorList, name)
	}

	for _, line := range argsToStrings(maxLastArgLength, monitorList, ",") {
		client.Send(nil, server.name, RPL_MONLIST, client.nick, line)
	}

	return false
}

func monitorStatusHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	var online []string
	var offline []string

	for name := range client.monitoring {
		target := server.clients.Get(name)
		if target == nil {
			offline = append(offline, name)
		} else {
			online = append(online, target.nickMaskString)
		}
	}

	if len(online) > 0 {
		for _, line := range argsToStrings(maxLastArgLength, online, ",") {
			client.Send(nil, server.name, RPL_MONONLINE, client.nick, line)
		}
	}
	if len(offline) > 0 {
		for _, line := range argsToStrings(maxLastArgLength, offline, ",") {
			client.Send(nil, server.name, RPL_MONOFFLINE, client.nick, line)
		}
	}

	return false
}
