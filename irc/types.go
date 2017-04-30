// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"strings"
	"sync"
)

// ChannelNameMap is a map that converts channel names to actual channel objects.
type ChannelNameMap struct {
	ChansLock sync.RWMutex
	Chans     map[string]*Channel
}

// NewChannelNameMap returns a new ChannelNameMap.
func NewChannelNameMap() *ChannelNameMap {
	var channels ChannelNameMap
	channels.Chans = make(map[string]*Channel)
	return &channels
}

// Get returns the given channel if it exists.
func (channels *ChannelNameMap) Get(name string) *Channel {
	name, err := CasefoldChannel(name)
	if err == nil {
		channels.ChansLock.RLock()
		defer channels.ChansLock.RUnlock()
		return channels.Chans[name]
	}
	return nil
}

// Add adds the given channel to our map.
func (channels *ChannelNameMap) Add(channel *Channel) error {
	channels.ChansLock.Lock()
	defer channels.ChansLock.Unlock()
	if channels.Chans[channel.nameCasefolded] != nil {
		return fmt.Errorf("%s: already set", channel.name)
	}
	channels.Chans[channel.nameCasefolded] = channel
	return nil
}

// Remove removes the given channel from our map.
func (channels *ChannelNameMap) Remove(channel *Channel) error {
	channels.ChansLock.Lock()
	defer channels.ChansLock.Unlock()
	if channel != channels.Chans[channel.nameCasefolded] {
		return fmt.Errorf("%s: mismatch", channel.name)
	}
	delete(channels.Chans, channel.nameCasefolded)
	return nil
}

// Len returns how many channels we have.
func (channels *ChannelNameMap) Len() int {
	channels.ChansLock.RLock()
	defer channels.ChansLock.RUnlock()
	return len(channels.Chans)
}

type ModeSet map[Mode]bool

func (set ModeSet) String() string {
	if len(set) == 0 {
		return ""
	}
	strs := make([]string, len(set))
	index := 0
	for mode := range set {
		strs[index] = mode.String()
		index++
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

type MemberSet map[*Client]ModeSet

func (members MemberSet) Add(member *Client) {
	members[member] = make(ModeSet)
}

func (members MemberSet) Remove(member *Client) {
	delete(members, member)
}

func (members MemberSet) Has(member *Client) bool {
	_, ok := members[member]
	return ok
}

func (members MemberSet) HasMode(member *Client, mode Mode) bool {
	modes, ok := members[member]
	if !ok {
		return false
	}
	return modes[mode]
}

func (members MemberSet) AnyHasMode(mode Mode) bool {
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
