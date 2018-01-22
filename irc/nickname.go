// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"strings"

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/oragono/oragono/irc/sno"
)

var (
	restrictedNicknames = map[string]bool{
		"=scene=":  true, // used for rp commands
		"chanserv": true,
		"nickserv": true,
	}
)

// NICK <nickname>
func nickHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	if !client.authorized {
		client.Quit("Bad password")
		return true
	}

	return performNickChange(server, client, client, msg.Params[0])
}

func performNickChange(server *Server, client *Client, target *Client, newnick string) bool {
	nickname := strings.TrimSpace(newnick)
	cfnick, err := CasefoldName(nickname)

	if len(nickname) < 1 {
		client.Send(nil, server.name, ERR_NONICKNAMEGIVEN, client.nick, client.t("No nickname given"))
		return false
	}

	if err != nil || len(nickname) > server.Limits().NickLen || restrictedNicknames[cfnick] {
		client.Send(nil, server.name, ERR_ERRONEUSNICKNAME, client.nick, nickname, client.t("Erroneous nickname"))
		return false
	}

	if target.Nick() == nickname {
		return false
	}

	hadNick := target.HasNick()
	origNick := target.Nick()
	origNickMask := target.NickMaskString()
	err = client.server.clients.SetNick(target, nickname)
	if err == ErrNicknameInUse {
		client.Send(nil, server.name, ERR_NICKNAMEINUSE, client.nick, nickname, client.t("Nickname is already in use"))
		return false
	} else if err != nil {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, "NICK", fmt.Sprintf(client.t("Could not set or change nickname: %s"), err.Error()))
		return false
	}

	client.server.logger.Debug("nick", fmt.Sprintf("%s changed nickname to %s [%s]", origNickMask, nickname, cfnick))
	if hadNick {
		target.server.snomasks.Send(sno.LocalNicks, fmt.Sprintf(ircfmt.Unescape("$%s$r changed nickname to %s"), origNick, nickname))
		target.server.whoWas.Append(client)
		for friend := range target.Friends() {
			friend.Send(nil, origNickMask, "NICK", nickname)
		}
	}

	if target.registered {
		client.server.monitorManager.AlertAbout(target, true)
	} else {
		server.tryRegister(target)
	}
	return false
}

// SANICK <oldnick> <nickname>
func sanickHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	targetNick := strings.TrimSpace(msg.Params[0])
	target := server.clients.Get(targetNick)
	if target == nil {
		client.Send(nil, server.name, ERR_NOSUCHNICK, client.nick, msg.Params[0], client.t("No such nick"))
		return false
	}
	return performNickChange(server, client, target, msg.Params[1])
}
