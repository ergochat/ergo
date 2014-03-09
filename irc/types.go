package irc

import (
	"fmt"
	"strings"
)

//
// simple types
//

type CapSubCommand string

type Capability string

func (capability Capability) String() string {
	return string(capability)
}

type CapModifier rune

func (mod CapModifier) String() string {
	return string(mod)
}

type CapState uint

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

// add, remove, list modes
type ModeOp rune

func (op ModeOp) String() string {
	return string(op)
}

// user mode flags
type UserMode rune

func (mode UserMode) String() string {
	return string(mode)
}

type Phase uint

type ReplyCode interface {
	String() string
}

type StringCode string

func (code StringCode) String() string {
	return string(code)
}

type NumericCode uint

func (code NumericCode) String() string {
	return fmt.Sprintf("%03d", code)
}

// channel mode flags
type ChannelMode rune

func (mode ChannelMode) String() string {
	return string(mode)
}

type ChannelNameMap map[string]*Channel

func (channels ChannelNameMap) Get(name string) *Channel {
	return channels[strings.ToLower(name)]
}

func (channels ChannelNameMap) Add(channel *Channel) error {
	if channels[channel.name] != nil {
		return fmt.Errorf("%s: already set", channel.name)
	}
	channels[channel.name] = channel
	return nil
}

func (channels ChannelNameMap) Remove(channel *Channel) error {
	if channel != channels[channel.name] {
		return fmt.Errorf("%s: mismatch", channel.name)
	}
	delete(channels, channel.name)
	return nil
}

type ChannelModeSet map[ChannelMode]bool

func (set ChannelModeSet) String() string {
	if len(set) == 0 {
		return ""
	}
	strs := make([]string, len(set))
	index := 0
	for mode := range set {
		strs[index] = mode.String()
		index += 1
	}
	return strings.Join(strs, "")
}

type ClientSet map[*Client]bool

func (clients ClientSet) Add(client *Client) {
	clients[client] = true
}

func (clients ClientSet) Remove(client *Client) {
	delete(clients, client)
}

func (clients ClientSet) Has(client *Client) bool {
	return clients[client]
}

type MemberSet map[*Client]ChannelModeSet

func (members MemberSet) Add(member *Client) {
	members[member] = make(ChannelModeSet)
}

func (members MemberSet) Remove(member *Client) {
	delete(members, member)
}

func (members MemberSet) Has(member *Client) bool {
	_, ok := members[member]
	return ok
}

func (members MemberSet) HasMode(member *Client, mode ChannelMode) bool {
	modes, ok := members[member]
	if !ok {
		return false
	}
	return modes[mode]
}

type ChannelSet map[*Channel]bool

func (channels ChannelSet) Add(channel *Channel) {
	channels[channel] = true
}

func (channels ChannelSet) Remove(channel *Channel) {
	delete(channels, channel)
}

func (channels ChannelSet) First() *Channel {
	for channel := range channels {
		return channel
	}
	return nil
}

//
// interfaces
//

type Identifier interface {
	Id() string
	Nick() string
}

type Replier interface {
	Reply(...string)
}

type Command interface {
	Code() StringCode
	Client() *Client
}

type ServerCommand interface {
	Command
	HandleServer(*Server)
}

type AuthServerCommand interface {
	Command
	HandleAuthServer(*Server)
}

type RegServerCommand interface {
	Command
	HandleRegServer(*Server)
}
