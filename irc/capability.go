// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"strings"

	"github.com/DanielOaks/girc-go/ircmsg"
)

// Capabilities are optional features a client may request from a server.
type Capability string

const (
	AccountTag      Capability = "account-tag"
	AccountNotify   Capability = "account-notify"
	AwayNotify      Capability = "away-notify"
	ExtendedJoin    Capability = "extended-join"
	MultiPrefix     Capability = "multi-prefix"
	SASL            Capability = "sasl"
	ServerTime      Capability = "server-time"
	UserhostInNames Capability = "userhost-in-names"
)

var (
	SupportedCapabilities = CapabilitySet{
		AccountTag:      true,
		AccountNotify:   true,
		AwayNotify:      true,
		ExtendedJoin:    true,
		MultiPrefix:     true,
		SASL:            true,
		ServerTime:      true,
		UserhostInNames: true,
	}
)

func (capability Capability) String() string {
	return string(capability)
}

// CapModifiers are indicators showing the state of a capability after a REQ or
// ACK.
type CapModifier rune

const (
	Ack     CapModifier = '~'
	Disable CapModifier = '-'
	Sticky  CapModifier = '='
)

func (mod CapModifier) String() string {
	return string(mod)
}

type CapState uint

const (
	CapNone        CapState = iota
	CapNegotiating CapState = iota
	CapNegotiated  CapState = iota
)

type CapabilitySet map[Capability]bool

func (set CapabilitySet) String() string {
	strs := make([]string, len(set))
	index := 0
	for capability := range set {
		strs[index] = string(capability)
		index += 1
	}
	return strings.Join(strs, " ")
}

func (set CapabilitySet) DisableString() string {
	parts := make([]string, len(set))
	index := 0
	for capability := range set {
		parts[index] = Disable.String() + capability.String()
		index += 1
	}
	return strings.Join(parts, " ")
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
				capabilities[Capability(str)] = true
			}
		}
	}

	switch subCommand {
	case "LS":
		if !client.registered {
			client.capState = CapNegotiating
		}
		// client.server needs to be here to workaround a parsing bug in weechat 1.4
		// and let it connect to the server (otherwise it doesn't respond to the CAP
		// message with anything and just hangs on connection)
		client.Send(nil, server.name, "CAP", client.nick, subCommand, SupportedCapabilities.String())

	case "LIST":
		client.Send(nil, server.name, "CAP", client.nick, subCommand, client.capabilities.String())

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
