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
	SupportedCapabilities = CapabilitySet{
		caps.AccountTag:    true,
		caps.AccountNotify: true,
		caps.AwayNotify:    true,
		caps.CapNotify:     true,
		caps.ChgHost:       true,
		caps.EchoMessage:   true,
		caps.ExtendedJoin:  true,
		caps.InviteNotify:  true,
		// MaxLine is set during server startup
		caps.MessageTags: true,
		caps.MultiPrefix: true,
		caps.Rename:      true,
		// SASL is set during server startup
		caps.ServerTime: true,
		// STS is set during server startup
		caps.UserhostInNames: true,
	}
	// CapValues are the actual values we advertise to v3.2 clients.
	CapValues = map[caps.Capability]string{
		caps.SASL: "PLAIN,EXTERNAL",
	}
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

// CapVersion is used to select which max version of CAP the client supports.
type CapVersion uint

const (
	// Cap301 refers to the base CAP spec.
	Cap301 CapVersion = 301
	// Cap302 refers to the IRCv3.2 CAP spec.
	Cap302 CapVersion = 302
)

// CapabilitySet is used to track supported, enabled, and existing caps.
type CapabilitySet map[caps.Capability]bool

func (set CapabilitySet) String(version CapVersion) string {
	strs := make([]string, len(set))
	index := 0
	for capability := range set {
		capString := string(capability)
		if version == Cap302 {
			val, exists := CapValues[capability]
			if exists {
				capString += "=" + val
			}
		}
		strs[index] = capString
		index++
	}
	return strings.Join(strs, " ")
}

// CAP <subcmd> [<caps>]
func capHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	subCommand := strings.ToUpper(msg.Params[0])
	capabilities := make(CapabilitySet)
	var capString string

	if len(msg.Params) > 1 {
		capString = msg.Params[1]
		strs := strings.Split(capString, " ")
		for _, str := range strs {
			if len(str) > 0 {
				capabilities[caps.Capability(str)] = true
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
		client.Send(nil, server.name, "CAP", client.nick, subCommand, SupportedCapabilities.String(client.capVersion))

	case "LIST":
		client.Send(nil, server.name, "CAP", client.nick, subCommand, client.capabilities.String(Cap301)) // values not sent on LIST so force 3.1

	case "REQ":
		// make sure all capabilities actually exist
		for capability := range capabilities {
			if !SupportedCapabilities[capability] {
				client.Send(nil, server.name, "CAP", client.nick, "NAK", capString)
				return false
			}
		}
		for capability := range capabilities {
			client.capabilities[capability] = true
		}
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
