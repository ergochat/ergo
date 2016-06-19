// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import "github.com/DanielOaks/girc-go/ircmsg"

// Command represents a command accepted from a client.
type Command struct {
	handler           func(server *Server, client *Client, msg ircmsg.IrcMessage) bool
	usablePreReg      bool
	leaveClientActive bool // if true, leaves the client active time alone. reversed because we can't default a struct element to True
	leaveClientIdle   bool
	minParams         int
}

// Run runs this command with the given client/message.
func (cmd *Command) Run(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if !client.registered && !cmd.usablePreReg {
		// command silently ignored
		return false
	}
	if len(msg.Params) < cmd.minParams {
		client.Send(nil, server.nameString, ERR_NEEDMOREPARAMS, client.nickString, msg.Command, "Not enough parameters")
		return false
	}
	if !cmd.leaveClientActive {
		client.Active()
	}
	if !cmd.leaveClientIdle {
		client.Touch()
	}
	exiting := cmd.handler(server, client, msg)

	// after each command, see if we can send registration to the client
	if !client.registered {
		server.tryRegister(client)
	}

	return exiting
}

// Commands holds all commands executable by a client connected to us.
var Commands = map[string]Command{
	"AWAY": Command{
		handler:   awayHandler,
		minParams: 0,
	},
	"CAP": Command{
		handler:      capHandler,
		usablePreReg: true,
		minParams:    1,
	},
	"DEBUG": Command{
		handler:   debugHandler,
		minParams: 1,
	},
	"INVITE": Command{
		handler:   inviteHandler,
		minParams: 2,
	},
	"ISON": Command{
		handler:   isonHandler,
		minParams: 1,
	},
	"JOIN": Command{
		handler:   joinHandler,
		minParams: 1,
	},
	"KICK": Command{
		handler:   kickHandler,
		minParams: 2,
	},
	"KILL": Command{
		handler:   killHandler,
		minParams: 2,
	},
	"LIST": Command{
		handler:   listHandler,
		minParams: 0,
	},
	/*TODO(dan): ADD THIS BACK.
	"MODE": Command{
		handler:   modeHandler,
		minParams: 1,
	},*/
	"MOTD": Command{
		handler:   motdHandler,
		minParams: 0,
	},
	"NAMES": Command{
		handler:   namesHandler,
		minParams: 0,
	},
	"NICK": Command{
		handler:      nickHandler,
		usablePreReg: true,
		minParams:    1,
	},
	"NOTICE": Command{
		handler:   noticeHandler,
		minParams: 2,
	},
	"ONICK": Command{
		handler:   onickHandler,
		minParams: 2,
	},
	"OPER": Command{
		handler:   operHandler,
		minParams: 2,
	},
	"PART": Command{
		handler:   partHandler,
		minParams: 1,
	},
	"PASS": Command{
		handler:      passHandler,
		usablePreReg: true,
		minParams:    1,
	},
	"PING": Command{
		handler:           pingHandler,
		usablePreReg:      true,
		minParams:         1,
		leaveClientActive: true,
	},
	"PONG": Command{
		handler:           pongHandler,
		usablePreReg:      true,
		minParams:         1,
		leaveClientActive: true,
	},
	"PRIVMSG": Command{
		handler:   privmsgHandler,
		minParams: 2,
	},
	"PROXY": Command{
		handler:      proxyHandler,
		usablePreReg: true,
		minParams:    5,
	},
	"QUIT": Command{
		handler:      quitHandler,
		usablePreReg: true,
		minParams:    0,
	},
	/*TODO(dan): ADD THIS BACK IN
	"THEATRE": Command{
		handler:   theatreHandler,
		minParams: 1,
	},*/
	"TIME": Command{
		handler:   timeHandler,
		minParams: 0,
	},
	"TOPIC": Command{
		handler:   topicHandler,
		minParams: 1,
	},
	"USER": Command{
		handler:      userHandler,
		usablePreReg: true,
		minParams:    4,
	},
	"VERSION": Command{
		handler:   versionHandler,
		minParams: 0,
	},
	"WHO": Command{
		handler:   whoHandler,
		minParams: 0,
	},
	"WHOIS": Command{
		handler:   whoisHandler,
		minParams: 1,
	},
	"WHOWAS": Command{
		handler:   whowasHandler,
		minParams: 1,
	},
}
