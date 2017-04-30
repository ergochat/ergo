// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"strings"

	"github.com/DanielOaks/girc-go/ircmsg"
)

// nsHandler handles the /NS and /NICKSERV commands
func nsHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	server.nickservReceivePrivmsg(client, strings.Join(msg.Params, " "))
	return false
}

func (server *Server) nickservReceiveNotice(client *Client, message string) {
	// do nothing
}

func (server *Server) nickservReceivePrivmsg(client *Client, message string) {
	client.Notice("NickServ is not yet implemented, sorry! To register an account, check /HELPOP REG")
}
