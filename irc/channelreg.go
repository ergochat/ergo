// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"encoding/json"
	"time"

	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/utils"
)

// this is exclusively the *persistence* layer for channel registration;
// channel creation/tracking/destruction is in channelmanager.go

// these are bit flags indicating what part of the channel status is "dirty"
// and needs to be read from memory and written to the db
const (
	IncludeInitial uint = 1 << iota
	IncludeTopic
	IncludeModes
	IncludeLists
	IncludeSettings
)

// this is an OR of all possible flags
const (
	IncludeAllAttrs = ^uint(0)
)

// RegisteredChannel holds details about a given registered channel.
type RegisteredChannel struct {
	// Name of the channel.
	Name string
	// UUID for the datastore.
	UUID utils.UUID
	// RegisteredAt represents the time that the channel was registered.
	RegisteredAt time.Time
	// Founder indicates the founder of the channel.
	Founder string
	// Topic represents the channel topic.
	Topic string
	// TopicSetBy represents the host that set the topic.
	TopicSetBy string
	// TopicSetTime represents the time the topic was set.
	TopicSetTime time.Time
	// Modes represents the channel modes
	Modes []modes.Mode
	// Key represents the channel key / password
	Key string
	// Forward is the forwarding/overflow (+f) channel
	Forward string
	// UserLimit is the user limit (0 for no limit)
	UserLimit int
	// AccountToUMode maps user accounts to their persistent channel modes (e.g., +q, +h)
	AccountToUMode map[string]modes.Mode
	// Bans represents the bans set on the channel.
	Bans map[string]MaskInfo
	// Excepts represents the exceptions set on the channel.
	Excepts map[string]MaskInfo
	// Invites represents the invite exceptions set on the channel.
	Invites map[string]MaskInfo
	// Settings are the chanserv-modifiable settings
	Settings ChannelSettings
	// Metadata set using the METADATA command
	Metadata map[string]string
}

func (r *RegisteredChannel) Serialize() ([]byte, error) {
	return json.Marshal(r)
}

func (r *RegisteredChannel) Deserialize(b []byte) (err error) {
	return json.Unmarshal(b, r)
}

type ChannelPurgeRecord struct {
	NameCasefolded string `json:"Name"`
	UUID           utils.UUID
	Oper           string
	PurgedAt       time.Time
	Reason         string
}

func (c *ChannelPurgeRecord) Serialize() ([]byte, error) {
	return json.Marshal(c)
}

func (c *ChannelPurgeRecord) Deserialize(b []byte) error {
	return json.Unmarshal(b, c)
}
