// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/ergochat/ergo/irc/history"
	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/sno"
	"github.com/ergochat/ergo/irc/utils"
	"github.com/ergochat/irc-go/ircfmt"
)

var (
	restrictedNicknames = []string{
		"=scene=", // used for rp commands
		"Global",  // global announcements on some networks
		// common services not implemented by us:
		"MemoServ", "BotServ", "OperServ",
	}

	restrictedCasefoldedNicks = make(utils.HashSet[string])
	restrictedSkeletons       = make(utils.HashSet[string])
)

func performNickChange(server *Server, client *Client, target *Client, session *Session, nickname string, rb *ResponseBuffer) error {
	details := target.Details()
	hadNick := details.nick != "*"
	origNickMask := details.nickMask
	isSanick := client != target

	assignedNickname, err, awayChanged := client.server.clients.SetNick(target, session, nickname, false)
	if err == errNicknameInUse {
		if !isSanick {
			rb.Add(nil, server.name, ERR_NICKNAMEINUSE, details.nick, utils.SafeErrorParam(nickname), client.t("Nickname is already in use"))
		} else {
			rb.Add(nil, server.name, "FAIL", "SANICK", "NICKNAME_IN_USE", utils.SafeErrorParam(nickname), client.t("Nickname is already in use"))
		}
	} else if err == errNicknameReserved {
		if !isSanick {
			// see #1594 for context: ERR_NICKNAMEINUSE can confuse clients if the nickname is not
			// literally in use:
			if !client.registered {
				rb.Add(nil, server.name, ERR_NICKNAMEINUSE, details.nick, utils.SafeErrorParam(nickname), client.t("Nickname is reserved by a different account"))
			}
			rb.Add(nil, server.name, "FAIL", "NICK", "NICKNAME_RESERVED", utils.SafeErrorParam(nickname), client.t("Nickname is reserved by a different account"))
		} else {
			rb.Add(nil, server.name, "FAIL", "SANICK", "NICKNAME_RESERVED", utils.SafeErrorParam(nickname), client.t("Nickname is reserved by a different account"))
		}
	} else if err == errNicknameInvalid {
		if !isSanick {
			rb.Add(nil, server.name, ERR_ERRONEUSNICKNAME, details.nick, utils.SafeErrorParam(nickname), client.t("Erroneous nickname"))
		} else {
			rb.Add(nil, server.name, "FAIL", "SANICK", "NICKNAME_INVALID", utils.SafeErrorParam(nickname), client.t("Erroneous nickname"))
		}
	} else if err == errNickAccountMismatch {
		// this used to use ERR_NICKNAMEINUSE, but it displayed poorly in some clients;
		// ERR_UNKNOWNERROR at least has a better chance of displaying our error text
		if !isSanick {
			rb.Add(nil, server.name, ERR_UNKNOWNERROR, details.nick, "NICK", client.t("You must use your account name as your nickname"))
		} else {
			rb.Add(nil, server.name, "FAIL", "SANICK", "UNKNOWN_ERROR", utils.SafeErrorParam(nickname), client.t("This user's nickname and account name need to be equal"))
		}
	} else if err == errNickMissing {
		if !isSanick {
			rb.Add(nil, server.name, ERR_NONICKNAMEGIVEN, details.nick, client.t("No nickname given"))
		} else {
			rb.Add(nil, server.name, "FAIL", "SANICK", "NICKNAME_INVALID", utils.SafeErrorParam(nickname), client.t("No nickname given"))
		}
	} else if err == errNoop {
		if !isSanick {
			// no message
		} else {
			rb.Add(nil, server.name, "NOTE", "SANICK", "NOOP", utils.SafeErrorParam(nickname), client.t("Client already had the desired nickname"))
		}
	} else if err != nil {
		client.server.logger.Error("internal", "couldn't change nick", nickname, err.Error())
		if !isSanick {
			rb.Add(nil, server.name, ERR_UNKNOWNERROR, details.nick, "NICK", client.t("Could not set or change nickname"))
		} else {
			rb.Add(nil, server.name, "FAIL", "SANICK", "UNKNOWN_ERROR", utils.SafeErrorParam(nickname), client.t("Could not set or change nickname"))
		}
	}
	if err != nil {
		return err
	}

	isBot := !isSanick && client.HasMode(modes.Bot)
	message := utils.MakeMessage("")
	histItem := history.Item{
		Type:        history.Nick,
		Nick:        origNickMask,
		AccountName: details.accountName,
		Message:     message,
		IsBot:       isBot,
	}
	histItem.Params[0] = assignedNickname

	client.server.logger.Debug("nick", fmt.Sprintf("%s changed nickname to %s [%s]", origNickMask, assignedNickname, client.NickCasefolded()))
	if hadNick {
		if client == target {
			target.server.snomasks.Send(sno.LocalNicks, fmt.Sprintf(ircfmt.Unescape("$%s$r changed nickname to %s"), details.nick, assignedNickname))
		} else {
			target.server.snomasks.Send(sno.LocalNicks, fmt.Sprintf(ircfmt.Unescape("Operator %s changed nickname of $%s$r to %s"), client.Nick(), details.nick, assignedNickname))
		}
		target.server.whoWas.Append(details.WhoWas)
		rb.AddFromClient(message.Time, message.Msgid, origNickMask, details.accountName, isBot, nil, "NICK", assignedNickname)
		for session := range target.Friends() {
			if session != rb.session {
				session.sendFromClientInternal(false, message.Time, message.Msgid, origNickMask, details.accountName, isBot, nil, "NICK", assignedNickname)
			}
		}
	}

	if awayChanged {
		dispatchAwayNotify(session.client, session.client.AwayMessage())
	}

	for _, channel := range target.Channels() {
		channel.AddHistoryItem(histItem, details.account)
	}

	newCfnick := target.NickCasefolded()
	if newCfnick != details.nickCasefolded {
		client.server.monitorManager.AlertAbout(details.nick, details.nickCasefolded, false)
		client.server.monitorManager.AlertAbout(assignedNickname, newCfnick, true)
	}
	return nil
}

func (server *Server) RandomlyRename(client *Client) {
	format := server.Config().Accounts.NickReservation.GuestFormat
	buf := make([]byte, 8)
	rand.Read(buf)
	nick := strings.Replace(format, "*", utils.B32Encoder.EncodeToString(buf), -1)
	sessions := client.Sessions()
	if len(sessions) == 0 {
		// this can happen if they are anonymous and BRB (in general, an always-on
		// client has title to its nickname and will never be the victim of
		// a call to RandomlyRename)
		client.destroy(nil)
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

// if force-nick-equals-account is set, account name and nickname must be equal,
// so we need to re-NICK automatically on every login event (IDENTIFY,
// VERIFY, and a REGISTER that auto-verifies). if we can't get the nick
// then we log them out (they will be able to reattach with SASL)
func fixupNickEqualsAccount(client *Client, rb *ResponseBuffer, config *Config, source string) (success bool) {
	if !config.Accounts.NickReservation.ForceNickEqualsAccount {
		return true
	}
	if !client.registered {
		return true
	}
	err := performNickChange(client.server, client, client, rb.session, client.AccountName(), rb)
	if err != nil && err != errNoop {
		client.server.accounts.Logout(client)
		if source == "" {
			source = client.server.name
		}
		rb.Add(nil, source, "NOTICE", client.t("A client is already using that account; try logging out and logging back in with SASL"))
		return false
	}
	return true
}
