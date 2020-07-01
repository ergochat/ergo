// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import "github.com/oragono/oragono/irc/modes"

type empty struct{}

// ClientSet is a set of clients.
type ClientSet map[*Client]empty

// Add adds the given client to this set.
func (clients ClientSet) Add(client *Client) {
	clients[client] = empty{}
}

// Remove removes the given client from this set.
func (clients ClientSet) Remove(client *Client) {
	delete(clients, client)
}

// Has returns true if the given client is in this set.
func (clients ClientSet) Has(client *Client) bool {
	_, ok := clients[client]
	return ok
}

type StringSet map[string]empty

func (s StringSet) Has(str string) bool {
	_, ok := s[str]
	return ok
}

func (s StringSet) Add(str string) {
	s[str] = empty{}
}

// MemberSet is a set of members with modes.
type MemberSet map[*Client]*modes.ModeSet

// Add adds the given client to this set.
func (members MemberSet) Add(member *Client) {
	members[member] = modes.NewModeSet()
}

// Remove removes the given client from this set.
func (members MemberSet) Remove(member *Client) {
	delete(members, member)
}

// Has returns true if the given client is in this set.
func (members MemberSet) Has(member *Client) bool {
	_, ok := members[member]
	return ok
}

// AnyHasMode returns true if any of our clients has the given mode.
func (members MemberSet) AnyHasMode(mode modes.Mode) bool {
	for _, modes := range members {
		if modes.HasMode(mode) {
			return true
		}
	}
	return false
}

// ChannelSet is a set of channels.
type ChannelSet map[*Channel]empty
