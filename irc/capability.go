// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"strings"

	"github.com/goshuirc/irc-go/ircmsg"
)

// Capability represents an optional feature that a client may request from the server.
type Capability string

const (
	// AccountNotify is this IRCv3 capability: http://ircv3.net/specs/extensions/account-notify-3.1.html
	AccountNotify Capability = "account-notify"
	// AccountTag is this IRCv3 capability: http://ircv3.net/specs/extensions/account-tag-3.2.html
	AccountTag Capability = "account-tag"
	// AwayNotify is this IRCv3 capability: http://ircv3.net/specs/extensions/away-notify-3.1.html
	AwayNotify Capability = "away-notify"
	// CapNotify is this IRCv3 capability: http://ircv3.net/specs/extensions/cap-notify-3.2.html
	CapNotify Capability = "cap-notify"
	// ChgHost is this IRCv3 capability: http://ircv3.net/specs/extensions/chghost-3.2.html
	ChgHost Capability = "chghost"
	// EchoMessage is this IRCv3 capability: http://ircv3.net/specs/extensions/echo-message-3.2.html
	EchoMessage Capability = "echo-message"
	// ExtendedJoin is this IRCv3 capability: http://ircv3.net/specs/extensions/extended-join-3.1.html
	ExtendedJoin Capability = "extended-join"
	// InviteNotify is this IRCv3 capability: http://ircv3.net/specs/extensions/invite-notify-3.2.html
	InviteNotify Capability = "invite-notify"
	// MaxLine is this proposed capability: https://github.com/DanielOaks/ircv3-specifications/blob/master+line-lengths/extensions/line-lengths.md
	MaxLine Capability = "draft/maxline"
	// MessageIDs is this draft IRCv3 capability: http://ircv3.net/specs/extensions/message-ids.html
	MessageIDs Capability = "draft/message-ids"
	// MessageTags is this draft IRCv3 capability: http://ircv3.net/specs/core/message-tags-3.3.html
	MessageTags Capability = "draft/message-tags-0.2"
	// MultiPrefix is this IRCv3 capability: http://ircv3.net/specs/extensions/multi-prefix-3.1.html
	MultiPrefix Capability = "multi-prefix"
	// Rename is this proposed capability: https://github.com/SaberUK/ircv3-specifications/blob/rename/extensions/rename.md
	Rename Capability = "draft/rename"
	// SASL is this IRCv3 capability: http://ircv3.net/specs/extensions/sasl-3.2.html
	SASL Capability = "sasl"
	// ServerTime is this IRCv3 capability: http://ircv3.net/specs/extensions/server-time-3.2.html
	ServerTime Capability = "server-time"
	// STS is this draft IRCv3 capability: http://ircv3.net/specs/core/sts-3.3.html
	STS Capability = "draft/sts"
	// UserhostInNames is this IRCv3 capability: http://ircv3.net/specs/extensions/userhost-in-names-3.2.html
	UserhostInNames Capability = "userhost-in-names"
)

var (
	// SupportedCapabilities are the caps we advertise.
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
		Rename:      true,
		// SASL is set during server startup
		ServerTime: true,
		// STS is set during server startup
		UserhostInNames: true,
	}
	// CapValues are the actual values we advertise to v3.2 clients.
	CapValues = map[Capability]string{
		SASL: "PLAIN,EXTERNAL",
	}
)

func (capability Capability) String() string {
	return string(capability)
}

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
