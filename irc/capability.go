package irc

import (
	"strings"
)

type CapSubCommand string

const (
	CAP_LS   CapSubCommand = "LS"
	CAP_LIST CapSubCommand = "LIST"
	CAP_REQ  CapSubCommand = "REQ"
	CAP_ACK  CapSubCommand = "ACK"
	CAP_NAK  CapSubCommand = "NAK"
	CAP_END  CapSubCommand = "END"
)

// Capabilities are optional features a client may request from a server.
type Capability string

const (
	MultiPrefix Capability = "multi-prefix"
	SASL        Capability = "sasl"
)

var (
	SupportedCapabilities = CapabilitySet{
		MultiPrefix: true,
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

func (msg *CapCommand) HandleRegServer(server *Server) {
	client := msg.Client()

	switch msg.subCommand {
	case CAP_LS:
		client.capState = CapNegotiating
		client.Reply(RplCap(client, CAP_LS, SupportedCapabilities))

	case CAP_LIST:
		client.Reply(RplCap(client, CAP_LIST, client.capabilities))

	case CAP_REQ:
		for capability := range msg.capabilities {
			if !SupportedCapabilities[capability] {
				client.Reply(RplCap(client, CAP_NAK, msg.capabilities))
				return
			}
		}
		for capability := range msg.capabilities {
			client.capabilities[capability] = true
		}
		client.Reply(RplCap(client, CAP_ACK, msg.capabilities))

	case CAP_END:
		client.capState = CapNegotiated
		server.tryRegister(client)

	default:
		client.ErrInvalidCapCmd(msg.subCommand)
	}
}

func (msg *CapCommand) HandleServer(server *Server) {
	client := msg.Client()

	switch msg.subCommand {
	case CAP_LS:
		client.Reply(RplCap(client, CAP_LS, SupportedCapabilities))

	case CAP_LIST:
		client.Reply(RplCap(client, CAP_LIST, client.capabilities))

	case CAP_REQ:
		for capability := range msg.capabilities {
			if !SupportedCapabilities[capability] {
				client.Reply(RplCap(client, CAP_NAK, msg.capabilities))
				return
			}
		}
		for capability := range msg.capabilities {
			client.capabilities[capability] = true
		}
		client.Reply(RplCap(client, CAP_ACK, msg.capabilities))

	case CAP_END:
		// no-op after registration performed
		return

	default:
		client.ErrInvalidCapCmd(msg.subCommand)
	}
}
