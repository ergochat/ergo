// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import "github.com/DanielOaks/girc-go/ircmsg"

// Command represents a command accepted from a client.
type Command struct {
	handler           func(server *Server, client *Client, msg ircmsg.IrcMessage) bool
	oper              bool
	usablePreReg      bool
	leaveClientActive bool // if true, leaves the client active time alone. reversed because we can't default a struct element to True
	leaveClientIdle   bool
	minParams         int
	capabs            []string
}

// Run runs this command with the given client/message.
func (cmd *Command) Run(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if !client.registered && !cmd.usablePreReg {
		client.Send(nil, server.name, ERR_NOTREGISTERED, client.nick, "You need to register before you can use that command")
		return false
	}
	if cmd.oper && !client.flags[Operator] {
		client.Send(nil, server.name, ERR_NOPRIVILEGES, client.nick, "Permission Denied - You're not an IRC operator")
		return false
	}
	if len(cmd.capabs) > 0 && !client.HasCapabs(cmd.capabs...) {
		client.Send(nil, server.name, ERR_NOPRIVILEGES, client.nick, "Permission Denied")
		return false
	}
	if len(msg.Params) < cmd.minParams {
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, msg.Command, "Not enough parameters")
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
	"AMBIANCE": {
		handler:   sceneHandler,
		minParams: 2,
	},
	"AUTHENTICATE": {
		handler:      authenticateHandler,
		usablePreReg: true,
		minParams:    1,
	},
	"AWAY": {
		handler:   awayHandler,
		minParams: 0,
	},
	"CAP": {
		handler:      capHandler,
		usablePreReg: true,
		minParams:    1,
	},
	"DEBUG": {
		handler:   debugHandler,
		minParams: 1,
	},
	"DLINE": {
		handler:   dlineHandler,
		minParams: 1,
		oper:      true,
	},
	"HELP": {
		handler:   helpHandler,
		minParams: 0,
	},
	"INVITE": {
		handler:   inviteHandler,
		minParams: 2,
	},
	"ISON": {
		handler:   isonHandler,
		minParams: 1,
	},
	"JOIN": {
		handler:   joinHandler,
		minParams: 1,
	},
	"KICK": {
		handler:   kickHandler,
		minParams: 2,
	},
	"KILL": {
		handler:   killHandler,
		minParams: 1,
		oper:      true,
		capabs:    []string{"oper:local_kill"}, //TODO(dan): when we have S2S, this will be checked in the command handler itself
	},
	"KLINE": {
		handler:   klineHandler,
		minParams: 1,
		oper:      true,
	},
	"LIST": {
		handler:   listHandler,
		minParams: 0,
	},
	"LUSERS": {
		handler:   lusersHandler,
		minParams: 0,
	},
	"MODE": {
		handler:   modeHandler,
		minParams: 1,
	},
	"MONITOR": {
		handler:   monitorHandler,
		minParams: 1,
	},
	"MOTD": {
		handler:   motdHandler,
		minParams: 0,
	},
	"NAMES": {
		handler:   namesHandler,
		minParams: 0,
	},
	"NICK": {
		handler:      nickHandler,
		usablePreReg: true,
		minParams:    1,
	},
	"NOTICE": {
		handler:   noticeHandler,
		minParams: 2,
	},
	"NPC": {
		handler:   npcHandler,
		minParams: 3,
	},
	"NPCA": {
		handler:   npcaHandler,
		minParams: 3,
	},
	"OPER": {
		handler:   operHandler,
		minParams: 2,
	},
	"PART": {
		handler:   partHandler,
		minParams: 1,
	},
	"PASS": {
		handler:      passHandler,
		usablePreReg: true,
		minParams:    1,
	},
	"PING": {
		handler:           pingHandler,
		usablePreReg:      true,
		minParams:         1,
		leaveClientActive: true,
	},
	"PONG": {
		handler:           pongHandler,
		usablePreReg:      true,
		minParams:         1,
		leaveClientActive: true,
	},
	"PRIVMSG": {
		handler:   privmsgHandler,
		minParams: 2,
	},
	"SANICK": {
		handler:   sanickHandler,
		minParams: 2,
		oper:      true,
	},
	"SCENE": {
		handler:   sceneHandler,
		minParams: 2,
	},
	"TAGMSG": {
		handler:   tagmsgHandler,
		minParams: 1,
	},
	"QUIT": {
		handler:      quitHandler,
		usablePreReg: true,
		minParams:    0,
	},
	"REG": {
		handler:   regHandler,
		minParams: 3,
	},
	"REHASH": {
		handler:   rehashHandler,
		minParams: 0,
		oper:      true,
		capabs:    []string{"oper:rehash"},
	},
	"TIME": {
		handler:   timeHandler,
		minParams: 0,
	},
	"TOPIC": {
		handler:   topicHandler,
		minParams: 1,
	},
	"UNDLINE": {
		handler:   unDLineHandler,
		minParams: 1,
		oper:      true,
	},
	"UNKLINE": {
		handler:   unKLineHandler,
		minParams: 1,
		oper:      true,
	},
	"USER": {
		handler:      userHandler,
		usablePreReg: true,
		minParams:    4,
	},
	"VERSION": {
		handler:   versionHandler,
		minParams: 0,
	},
	"WHO": {
		handler:   whoHandler,
		minParams: 0,
	},
	"WHOIS": {
		handler:   whoisHandler,
		minParams: 1,
	},
	"WHOWAS": {
		handler:   whowasHandler,
		minParams: 1,
	},
}
