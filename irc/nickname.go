// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/oragono/oragono/irc/history"
	"github.com/oragono/oragono/irc/sno"
	"github.com/oragono/oragono/irc/utils"
)

var (
	restrictedNicknames = []string{
		"=scene=",  // used for rp commands
		"HistServ", // used to play back JOIN, PART, etc. to legacy clients
	}

	restrictedCasefoldedNicks = make(map[string]bool)
	restrictedSkeletons       = make(map[string]bool)
)

// returns whether the change succeeded or failed
func performNickChange(server *Server, client *Client, target *Client, session *Session, newnick string, rb *ResponseBuffer) bool {
	nickname := strings.TrimSpace(newnick)
	currentNick := client.Nick()

	if len(nickname) < 1 {
		rb.Add(nil, server.name, ERR_NONICKNAMEGIVEN, currentNick, client.t("No nickname given"))
		return false
	}

	if target.Nick() == nickname {
		return true
	}

	hadNick := target.HasNick()
	origNickMask := target.NickMaskString()
	details := target.Details()
	err := client.server.clients.SetNick(target, session, nickname)
	if err == errNicknameInUse {
		rb.Add(nil, server.name, ERR_NICKNAMEINUSE, currentNick, nickname, client.t("Nickname is already in use"))
	} else if err == errNicknameReserved {
		rb.Add(nil, server.name, ERR_NICKNAMEINUSE, currentNick, nickname, client.t("Nickname is reserved by a different account"))
	} else if err == errNicknameInvalid {
		rb.Add(nil, server.name, ERR_ERRONEUSNICKNAME, currentNick, utils.SafeErrorParam(nickname), client.t("Erroneous nickname"))
	} else if err != nil {
		rb.Add(nil, server.name, ERR_UNKNOWNERROR, currentNick, "NICK", fmt.Sprintf(client.t("Could not set or change nickname: %s"), err.Error()))
	}
	if err != nil {
		return false
	}

	message := utils.MakeSplitMessage("", true)
	histItem := history.Item{
		Type:        history.Nick,
		Nick:        origNickMask,
		AccountName: details.accountName,
		Message:     message,
	}
	histItem.Params[0] = nickname

	client.server.logger.Debug("nick", fmt.Sprintf("%s changed nickname to %s [%s]", origNickMask, nickname, client.NickCasefolded()))
	if hadNick {
		if client == target {
			target.server.snomasks.Send(sno.LocalNicks, fmt.Sprintf(ircfmt.Unescape("$%s$r changed nickname to %s"), details.nick, nickname))
		} else {
			target.server.snomasks.Send(sno.LocalNicks, fmt.Sprintf(ircfmt.Unescape("Operator %s changed nickname of $%s$r to %s"), client.Nick(), details.nick, nickname))
		}
		target.server.whoWas.Append(details.WhoWas)
		rb.AddFromClient(message.Time, message.Msgid, origNickMask, details.accountName, nil, "NICK", nickname)
		for session := range target.Friends() {
			if session != rb.session {
				session.sendFromClientInternal(false, message.Time, message.Msgid, origNickMask, details.accountName, nil, "NICK", nickname)
			}
		}
	}

	for _, channel := range client.Channels() {
		channel.history.Add(histItem)
	}

	if target.Registered() {
		client.server.monitorManager.AlertAbout(target, true)
		target.nickTimer.Touch(rb)
	} // else: these will be deferred to the end of registration (see #572)
	return true
}

func (server *Server) RandomlyRename(client *Client) {
	prefix := server.AccountConfig().NickReservation.RenamePrefix
	if prefix == "" {
		prefix = "Guest-"
	}
	buf := make([]byte, 8)
	rand.Read(buf)
	nick := fmt.Sprintf("%s%s", prefix, hex.EncodeToString(buf))
	sessions := client.Sessions()
	if len(sessions) == 0 {
		return
	}
	// XXX arbitrarily pick the first session to receive error messages;
	// all other sessions receive a `NICK` line same as a friend would
	rb := NewResponseBuffer(sessions[0])
	performNickChange(server, client, client, nil, nick, rb)
	rb.Send(false)
	// technically performNickChange can fail to change the nick,
	// but if they're still delinquent, the timer will get them later
}
