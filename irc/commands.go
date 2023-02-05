// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"github.com/ergochat/irc-go/ircmsg"
)

// Command represents a command accepted from a client.
type Command struct {
	handler        func(server *Server, client *Client, msg ircmsg.Message, rb *ResponseBuffer) bool
	usablePreReg   bool
	allowedInBatch bool // allowed in client-to-server batches
	minParams      int
	capabs         []string
}

// Run runs this command with the given client/message.
func (cmd *Command) Run(server *Server, client *Client, session *Session, msg ircmsg.Message) (exiting bool) {
	rb := NewResponseBuffer(session)
	rb.Label = GetLabel(msg)

	exiting = func() bool {
		defer rb.Send(true)

		if !client.registered && !cmd.usablePreReg {
			rb.Add(nil, server.name, ERR_NOTREGISTERED, "*", client.t("You need to register before you can use that command"))
			return false
		}
		if len(cmd.capabs) > 0 && !client.HasRoleCapabs(cmd.capabs...) {
			rb.Add(nil, server.name, ERR_NOPRIVILEGES, client.Nick(), client.t("Permission Denied"))
			return false
		}
		if len(msg.Params) < cmd.minParams {
			rb.Add(nil, server.name, ERR_NEEDMOREPARAMS, client.Nick(), msg.Command, rb.target.t("Not enough parameters"))
			return false
		}
		if session.batch.label != "" && !cmd.allowedInBatch {
			rb.Add(nil, server.name, "FAIL", "BATCH", "MULTILINE_INVALID", client.t("Command not allowed during a multiline batch"))
			session.EndMultilineBatch("")
			return false
		}

		return cmd.handler(server, client, msg, rb)
	}()

	// after each command, see if we can send registration to the client
	if !exiting && !client.registered {
		exiting = server.tryRegister(client, session)
	}

	if client.registered {
		client.Touch(session) // even if `exiting`, we bump the lastSeen timestamp
	}

	return exiting
}

// fake handler for unknown commands (see #994: this ensures the response tags are correct)
var unknownCommand = Command{
	handler:      unknownCommandHandler,
	usablePreReg: true,
}

var invalidUtf8Command = Command{
	handler:      invalidUtf8Handler,
	usablePreReg: true,
}

// Commands holds all commands executable by a client connected to us.
var Commands map[string]Command

func init() {
	Commands = map[string]Command{
		"ACCEPT": {
			handler:   acceptHandler,
			minParams: 1,
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
			handler:      awayHandler,
			usablePreReg: true,
			minParams:    0,
		},
		"BATCH": {
			handler:        batchHandler,
			minParams:      1,
			allowedInBatch: true,
		},
		"CAP": {
			handler:      capHandler,
			usablePreReg: true,
			minParams:    1,
		},
		"CHATHISTORY": {
			handler:   chathistoryHandler,
			minParams: 4,
		},
		"DEBUG": {
			handler:   debugHandler,
			minParams: 1,
			capabs:    []string{"rehash"},
		},
		"DEFCON": {
			handler: defconHandler,
			capabs:  []string{"defcon"},
		},
		"DEOPER": {
			handler:   deoperHandler,
			minParams: 0,
		},
		"DLINE": {
			handler:   dlineHandler,
			minParams: 1,
			capabs:    []string{"ban"},
		},
		"EXTJWT": {
			handler:   extjwtHandler,
			minParams: 1,
		},
		"HELP": {
			handler:   helpHandler,
			minParams: 0,
		},
		"HELPOP": {
			handler:   helpHandler,
			minParams: 0,
		},
		"HISTORY": {
			handler:   historyHandler,
			minParams: 1,
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
			capabs:    []string{"kill"},
		},
		"KLINE": {
			handler:   klineHandler,
			minParams: 1,
			capabs:    []string{"ban"},
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
		"MARKREAD": {
			handler:   markReadHandler,
			minParams: 0, // send FAIL instead of ERR_NEEDMOREPARAMS
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
			handler:        messageHandler,
			minParams:      2,
			allowedInBatch: true,
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
			minParams: 1,
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
		"PERSISTENCE": {
			handler:   persistenceHandler,
			minParams: 1,
		},
		"PING": {
			handler:      pingHandler,
			usablePreReg: true,
			minParams:    1,
		},
		"PONG": {
			handler:      pongHandler,
			usablePreReg: true,
			minParams:    1,
		},
		"PRIVMSG": {
			handler:        messageHandler,
			minParams:      2,
			allowedInBatch: true,
		},
		"RELAYMSG": {
			handler:   relaymsgHandler,
			minParams: 3,
		},
		"REGISTER": {
			handler:      registerHandler,
			minParams:    3,
			usablePreReg: true,
		},
		"RENAME": {
			handler:   renameHandler,
			minParams: 2,
		},
		"SAJOIN": {
			handler:   sajoinHandler,
			minParams: 1,
			capabs:    []string{"sajoin"},
		},
		"SANICK": {
			handler:   sanickHandler,
			minParams: 2,
			capabs:    []string{"samode"},
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
		"SETNAME": {
			handler:   setnameHandler,
			minParams: 1,
		},
		"SUMMON": {
			handler: summonHandler,
		},
		"TAGMSG": {
			handler:   messageHandler,
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
			capabs:    []string{"rehash"},
		},
		"TIME": {
			handler:   timeHandler,
			minParams: 0,
		},
		"TOPIC": {
			handler:   topicHandler,
			minParams: 1,
		},
		"UBAN": {
			handler:   ubanHandler,
			minParams: 1,
			capabs:    []string{"ban"},
		},
		"UNDLINE": {
			handler:   unDLineHandler,
			minParams: 1,
			capabs:    []string{"ban"},
		},
		"UNINVITE": {
			handler:   inviteHandler,
			minParams: 2,
		},
		"UNKLINE": {
			handler:   unKLineHandler,
			minParams: 1,
			capabs:    []string{"ban"},
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
		"USERS": {
			handler: usersHandler,
		},
		"VERIFY": {
			handler:      verifyHandler,
			usablePreReg: true,
			minParams:    2,
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
		"ZNC": {
			handler:   zncHandler,
			minParams: 1,
		},
	}

	initializeServices()
}
