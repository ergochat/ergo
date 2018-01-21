// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"strings"

	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/oragono/oragono/irc/caps"
)

var (
	// SupportedCapabilities are the caps we advertise.
	// MaxLine, SASL and STS are set during server startup.
	SupportedCapabilities = caps.NewSet(caps.AccountTag, caps.AccountNotify, caps.AwayNotify, caps.CapNotify, caps.ChgHost, caps.EchoMessage, caps.ExtendedJoin, caps.InviteNotify, caps.Languages, caps.MessageTags, caps.MultiPrefix, caps.Rename, caps.Resume, caps.ServerTime, caps.UserhostInNames)

	// CapValues are the actual values we advertise to v3.2 clients.
	// actual values are set during server startup.
	CapValues = caps.NewValues()
)

// CapState shows whether we're negotiating caps, finished, etc for connection registration.
type CapState uint

const (
	// CapNone means CAP hasn't been negotiated at all.
	CapNone CapState = iota
	// CapNegotiating means CAP is being negotiated and registration should be paused.
	CapNegotiating CapState = iota
	// CapNegotiated means CAP negotiation has been successfully ended and reg should complete.
	CapNegotiated CapState = iota
)

// CAP <subcmd> [<caps>]
func capHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	subCommand := strings.ToUpper(msg.Params[0])
	capabilities := caps.NewSet()
	var capString string

	if len(msg.Params) > 1 {
		capString = msg.Params[1]
		strs := strings.Split(capString, " ")
		for _, str := range strs {
			if len(str) > 0 {
				capabilities.Enable(caps.Capability(str))
			}
		}
	}

	switch subCommand {
	case "LS":
		if !client.registered {
			client.capState = CapNegotiating
		}
		if len(msg.Params) > 1 && msg.Params[1] == "302" {
			client.capVersion = 302
		}
		// weechat 1.4 has a bug here where it won't accept the CAP reply unless it contains
		// the server.name source... otherwise it doesn't respond to the CAP message with
		// anything and just hangs on connection.
		//TODO(dan): limit number of caps and send it multiline in 3.2 style as appropriate.
		client.Send(nil, server.name, "CAP", client.nick, subCommand, SupportedCapabilities.String(client.capVersion, CapValues))

	case "LIST":
		client.Send(nil, server.name, "CAP", client.nick, subCommand, client.capabilities.String(caps.Cap301, CapValues)) // values not sent on LIST so force 3.1

	case "REQ":
		if !client.registered {
			client.capState = CapNegotiating
		}

		// make sure all capabilities actually exist
		for _, capability := range capabilities.List() {
			if !SupportedCapabilities.Has(capability) {
				client.Send(nil, server.name, "CAP", client.nick, "NAK", capString)
				return false
			}
		}
		client.capabilities.Enable(capabilities.List()...)
		client.Send(nil, server.name, "CAP", client.nick, "ACK", capString)

	case "END":
		if !client.registered {
			client.capState = CapNegotiated
			server.tryRegister(client)
		}

	default:
		client.Send(nil, server.name, ERR_INVALIDCAPCMD, client.nick, subCommand, "Invalid CAP subcommand")
	}
	return false
}
