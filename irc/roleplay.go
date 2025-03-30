// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"strings"

	"github.com/ergochat/ergo/irc/history"
	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/utils"
)

const (
	defaultNPCNickMask   = "*%s*!%s@npc.fakeuser.invalid"
	defaultSceneNickMask = "=Scene=!%s@npc.fakeuser.invalid"
)

func sendRoleplayMessage(server *Server, client *Client, source string, targetString string, isScene, isAction bool, messageParts []string, rb *ResponseBuffer) {
	config := server.Config()
	if !config.Roleplay.Enabled {
		rb.Add(nil, client.server.name, ERR_CANNOTSENDRP, targetString, client.t("Roleplaying has been disabled by the server administrators"))
		return
	}
	if config.Roleplay.RequireOper && !client.HasRoleCapabs("roleplay") {
		rb.Add(nil, client.server.name, ERR_CANNOTSENDRP, targetString, client.t("Insufficient privileges"))
		return
	}

	var sourceMask string
	if isScene {
		sourceMask = fmt.Sprintf(server.Config().Roleplay.SceneNickMask, client.Nick())
	} else {
		cfSource, cfSourceErr := CasefoldName(source)
		skelSource, skelErr := Skeleton(source)
		if cfSourceErr != nil || skelErr != nil ||
			restrictedCasefoldedNicks.Has(cfSource) || restrictedSkeletons.Has(skelSource) {
			rb.Add(nil, client.server.name, ERR_CANNOTSENDRP, targetString, client.t("Invalid roleplay name"))
			return
		}
		sourceMask = fmt.Sprintf(server.Config().Roleplay.NPCNickMask, source, client.Nick())
	}

	// block attempts to send CTCP messages to Tor clients
	if len(messageParts) > 0 && len(messageParts[0]) > 0 && messageParts[0][0] == '\x01' {
		return
	}

	var buf strings.Builder
	if isAction {
		buf.WriteString("\x01ACTION ")
	}
	for i, part := range messageParts {
		buf.WriteString(part)
		if i != len(messageParts)-1 {
			buf.WriteByte(' ')
		}
	}
	if config.Roleplay.addSuffix {
		buf.WriteString(" (")
		buf.WriteString(client.Nick())
		buf.WriteString(")")
	}
	if isAction {
		buf.WriteString("\x01")
	}

	splitMessage := utils.MakeMessage(buf.String())

	target, cerr := CasefoldChannel(targetString)
	if cerr == nil {
		channel := server.channels.Get(target)
		if channel == nil {
			rb.Add(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, targetString, client.t("No such channel"))
			return
		}

		targetString = channel.Name()
		if canSpeak, mode := channel.CanSpeak(client); !canSpeak {
			rb.Add(nil, client.server.name, ERR_CANNOTSENDTOCHAN, targetString, fmt.Sprintf(client.t("Cannot send to channel (+%s)"), mode))
			return
		}

		if !channel.flags.HasMode(modes.ChanRoleplaying) {
			rb.Add(nil, client.server.name, ERR_CANNOTSENDRP, targetString, client.t("Channel doesn't have roleplaying mode available"))
			return
		}

		if config.Roleplay.RequireChanops && !channel.ClientIsAtLeast(client, modes.ChannelOperator) {
			rb.Add(nil, client.server.name, ERR_CANNOTSENDRP, targetString, client.t("Insufficient privileges"))
			return
		}

		isBot := client.HasMode(modes.Bot)
		for _, member := range channel.Members() {
			for _, session := range member.Sessions() {
				// see discussion on #865: clients do not understand how to do local echo
				// of roleplay commands, so send them a copy whether they have echo-message
				// or not
				if rb.session == session {
					rb.AddSplitMessageFromClient(sourceMask, "*", isBot, nil, "PRIVMSG", targetString, splitMessage)
				} else {
					session.sendSplitMsgFromClientInternal(false, sourceMask, "*", isBot, nil, "PRIVMSG", targetString, splitMessage)
				}
			}
		}

		channel.AddHistoryItem(history.Item{
			Type:    history.Privmsg,
			Message: splitMessage,
			Nick:    sourceMask,
		}, client.Account())
	} else {
		target, err := CasefoldName(targetString)
		user := server.clients.Get(target)
		if err != nil || user == nil {
			rb.Add(nil, server.name, ERR_NOSUCHNICK, client.nick, target, client.t("No such nick"))
			return
		}

		if !user.HasMode(modes.UserRoleplaying) {
			rb.Add(nil, client.server.name, ERR_CANNOTSENDRP, user.nick, client.t("User doesn't have roleplaying mode enabled"))
			return
		}

		cnick := client.Nick()
		tnick := user.Nick()
		isBot := client.HasMode(modes.Bot)
		for _, session := range user.Sessions() {
			session.sendSplitMsgFromClientInternal(false, sourceMask, "*", isBot, nil, "PRIVMSG", tnick, splitMessage)
		}
		if away, awayMessage := user.Away(); away {
			//TODO(dan): possibly implement cooldown of away notifications to users
			rb.Add(nil, server.name, RPL_AWAY, cnick, tnick, awayMessage)
		}
	}
}
