// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/oragono/oragono/irc/modes"
)

// Command represents a command accepted from a client.
type Command struct {
	handler           func(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool
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
		client.Send(nil, server.name, ERR_NOTREGISTERED, client.nick, client.t("You need to register before you can use that command"))
		return false
	}
	if cmd.oper && !client.HasMode(modes.Operator) {
		client.Send(nil, server.name, ERR_NOPRIVILEGES, client.nick, client.t("Permission Denied - You're not an IRC operator"))
		return false
	}
	if len(cmd.capabs) > 0 && !client.HasRoleCapabs(cmd.capabs...) {
		client.Send(nil, server.name, ERR_NOPRIVILEGES, client.nick, client.t("Permission Denied"))
		return false
	}
	if len(msg.Params) < cmd.minParams {
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, msg.Command, client.t("Not enough parameters"))
		return false
	}

	rb := NewResponseBuffer(client)
	rb.Label = GetLabel(msg)

	exiting := cmd.handler(server, client, msg, rb)

	rb.Send()

	// after each command, see if we can send registration to the client
	if !client.registered {
		server.tryRegister(client)
	}

	if !cmd.leaveClientIdle {
		client.Touch()
	}

	if !cmd.leaveClientActive {
		client.Active()
	}

	return exiting
}

// Commands holds all commands executable by a client connected to us.
var Commands map[string]Command

func init() {
	Commands = map[string]Command{
		"ACC": {
			handler:   accHandler,
			minParams: 2,
		},
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
		"CHANSERV": {
			handler:   csHandler,
			minParams: 1,
		},
		"CS": {
			handler:   csHandler,
			minParams: 1,
		},
		"DEBUG": {
			handler:   debugHandler,
			minParams: 1,
			oper:      true,
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
		"HELPOP": {
			handler:   helpHandler,
			minParams: 0,
		},
		"INFO": {
			handler: infoHandler,
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
		"LANGUAGE": {
			handler:      languageHandler,
			usablePreReg: true,
			minParams:    1,
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
		"NICKSERV": {
			handler:   nsHandler,
			minParams: 1,
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
		"NS": {
			handler:   nsHandler,
			minParams: 1,
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
		"PROXY": {
			handler:      proxyHandler,
			usablePreReg: true,
			minParams:    5,
		},
		"RENAME": {
			handler:   renameHandler,
			minParams: 2,
		},
		"RESUME": {
			handler:      resumeHandler,
			usablePreReg: true,
			minParams:    1,
		},
		"SANICK": {
			handler:   sanickHandler,
			minParams: 2,
			oper:      true,
		},
		"SAMODE": {
			handler:   modeHandler,
			minParams: 1,
			capabs:    []string{"samode"},
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
		"USERHOST": {
			handler:   userhostHandler,
			minParams: 1,
		},
		"VERSION": {
			handler:   versionHandler,
			minParams: 0,
		},
		"WEBIRC": {
			handler:      webircHandler,
			usablePreReg: true,
			minParams:    4,
		},
		"WHO": {
			handler:   whoHandler,
			minParams: 1,
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
}
