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
	CapNotify       Capability = "cap-notify"
	ChgHost         Capability = "chghost"
	EchoMessage     Capability = "echo-message"
	ExtendedJoin    Capability = "extended-join"
	InviteNotify    Capability = "invite-notify"
	MaxLine         Capability = "draft/maxline"
	MessageIDs      Capability = "draft/message-ids"
	MessageTags     Capability = "draft/message-tags-0.2"
	MultiPrefix     Capability = "multi-prefix"
	SASL            Capability = "sasl"
	ServerTime      Capability = "server-time"
	UserhostInNames Capability = "userhost-in-names"
)

var (
	SupportedCapabilities = CapabilitySet{
		AccountTag:    true,
		AccountNotify: true,
		AwayNotify:    true,
		CapNotify:     true,
		ChgHost:       true,
		EchoMessage:   true,
		ExtendedJoin:  true,
		InviteNotify:  true,
		MessageIDs:    true,
		// MaxLine is set during server startup
		MessageTags: true,
		MultiPrefix: true,
		// SASL is set during server startup
		ServerTime:      true,
		UserhostInNames: true,
	}
	CapValues = map[Capability]string{
		SASL: "PLAIN,EXTERNAL",
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

// CapVersion is used to select which max version of CAP the client supports.
type CapVersion uint

const (
	// Cap301 refers to the base CAP spec.
	Cap301 CapVersion = 301
	// Cap302 refers to the IRCv3.2 CAP spec.
	Cap302 CapVersion = 302
)

// CapabilitySet is used to track supported, enabled, and existing caps.
type CapabilitySet map[Capability]bool

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
