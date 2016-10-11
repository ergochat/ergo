// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// released under the MIT license

package irc

import (
	"fmt"
	"strings"
)

//
// simple types
//

type ChannelNameMap map[string]*Channel

func (channels ChannelNameMap) Get(name string) *Channel {
	name, err := CasefoldChannel(name)
	if err == nil {
		return channels[name]
	}
	return nil
}

func (channels ChannelNameMap) Add(channel *Channel) error {
	if channels[channel.nameCasefolded] != nil {
		return fmt.Errorf("%s: already set", channel.name)
	}
	channels[channel.nameCasefolded] = channel
	return nil
}

func (channels ChannelNameMap) Remove(channel *Channel) error {
	if channel != channels[channel.nameCasefolded] {
		return fmt.Errorf("%s: mismatch", channel.name)
	}
	delete(channels, channel.nameCasefolded)
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

func (members MemberSet) AnyHasMode(mode ChannelMode) bool {
	for _, modes := range members {
		if modes[mode] {
			return true
		}
	}
	return false
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

type Identifiable interface {
	Id() string
	Nick() string
}
