// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"time"

	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/utils"
)

// ClientSet is a set of clients.
type ClientSet = utils.HashSet[*Client]

type memberData struct {
	modes    modes.ModeSet
	joinTime int64
}

// MemberSet is a set of members with modes.
type MemberSet map[*Client]*memberData

// Add adds the given client to this set.
func (members MemberSet) Add(member *Client) {
	members[member] = &memberData{
		joinTime: time.Now().UnixNano(),
	}
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

// ChannelSet is a set of channels.
type ChannelSet = utils.HashSet[*Channel]
