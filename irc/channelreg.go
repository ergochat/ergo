// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"encoding/json"

	"github.com/oragono/oragono/irc/modes"
	"github.com/tidwall/buntdb"
)

// this is exclusively the *persistence* layer for channel registration;
// channel creation/tracking/destruction is in channelmanager.go

const (
	keyChannelExists         = "channel.exists %s"
	keyChannelName           = "channel.name %s" // stores the 'preferred name' of the channel, not casemapped
	keyChannelRegTime        = "channel.registered.time %s"
	keyChannelFounder        = "channel.founder %s"
	keyChannelTopic          = "channel.topic %s"
	keyChannelTopicSetBy     = "channel.topic.setby %s"
	keyChannelTopicSetTime   = "channel.topic.settime %s"
	keyChannelBanlist        = "channel.banlist %s"
	keyChannelExceptlist     = "channel.exceptlist %s"
	keyChannelInvitelist     = "channel.invitelist %s"
	keyChannelPassword       = "channel.key %s"
	keyChannelModes          = "channel.modes %s"
	keyChannelAccountToUMode = "channel.accounttoumode %s"
)

var (
	channelKeyStrings = []string{
		keyChannelExists,
		keyChannelName,
		keyChannelRegTime,
		keyChannelFounder,
		keyChannelTopic,
		keyChannelTopicSetBy,
		keyChannelTopicSetTime,
		keyChannelBanlist,
		keyChannelExceptlist,
		keyChannelInvitelist,
		keyChannelPassword,
		keyChannelModes,
		keyChannelAccountToUMode,
	}
)

// these are bit flags indicating what part of the channel status is "dirty"
// and needs to be read from memory and written to the db
const (
	IncludeInitial uint = 1 << iota
	IncludeTopic
	IncludeModes
	IncludeLists
)

// this is an OR of all possible flags
const (
	IncludeAllChannelAttrs = ^uint(0)
)

// RegisteredChannel holds details about a given registered channel.
type RegisteredChannel struct {
	// Name of the channel.
	Name string
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
	// AccountToUMode maps user accounts to their persistent channel modes (e.g., +q, +h)
	AccountToUMode map[string]modes.Mode
	// Banlist represents the bans set on the channel.
	Banlist []string
	// Exceptlist represents the exceptions set on the channel.
	Exceptlist []string
	// Invitelist represents the invite exceptions set on the channel.
	Invitelist []string
}

// ChannelRegistry manages registered channels.
type ChannelRegistry struct {
	// This serializes operations of the form (read channel state, synchronously persist it);
	// this is enough to guarantee eventual consistency of the database with the
	// ChannelManager and Channel objects, which are the source of truth.
	//
	// We could use the buntdb RW transaction lock for this purpose but we share
	// that with all the other modules, so let's not.
	sync.Mutex // tier 2
	server     *Server
}

// NewChannelRegistry returns a new ChannelRegistry.
func NewChannelRegistry(server *Server) *ChannelRegistry {
	return &ChannelRegistry{
		server: server,
	}
}

// StoreChannel obtains a consistent view of a channel, then persists it to the store.
func (reg *ChannelRegistry) StoreChannel(channel *Channel, includeFlags uint) {
	if !reg.server.ChannelRegistrationEnabled() {
		return
	}

	reg.Lock()
	defer reg.Unlock()

	key := channel.NameCasefolded()
	info := channel.ExportRegistration(includeFlags)
	if info.Founder == "" {
		// sanity check, don't try to store an unregistered channel
		return
	}

	reg.server.store.Update(func(tx *buntdb.Tx) error {
		reg.saveChannel(tx, key, info, includeFlags)
		return nil
	})
}

// LoadChannel loads a channel from the store.
func (reg *ChannelRegistry) LoadChannel(nameCasefolded string) (info *RegisteredChannel) {
	if !reg.server.ChannelRegistrationEnabled() {
		return nil
	}

	channelKey := nameCasefolded
	// nice to have: do all JSON (de)serialization outside of the buntdb transaction
	reg.server.store.View(func(tx *buntdb.Tx) error {
		_, err := tx.Get(fmt.Sprintf(keyChannelExists, channelKey))
		if err == buntdb.ErrNotFound {
			// chan does not already exist, return
			return nil
		}

		// channel exists, load it
		name, _ := tx.Get(fmt.Sprintf(keyChannelName, channelKey))
		regTime, _ := tx.Get(fmt.Sprintf(keyChannelRegTime, channelKey))
		regTimeInt, _ := strconv.ParseInt(regTime, 10, 64)
		founder, _ := tx.Get(fmt.Sprintf(keyChannelFounder, channelKey))
		topic, _ := tx.Get(fmt.Sprintf(keyChannelTopic, channelKey))
		topicSetBy, _ := tx.Get(fmt.Sprintf(keyChannelTopicSetBy, channelKey))
		topicSetTime, _ := tx.Get(fmt.Sprintf(keyChannelTopicSetTime, channelKey))
		topicSetTimeInt, _ := strconv.ParseInt(topicSetTime, 10, 64)
		password, _ := tx.Get(fmt.Sprintf(keyChannelPassword, channelKey))
		modeString, _ := tx.Get(fmt.Sprintf(keyChannelModes, channelKey))
		banlistString, _ := tx.Get(fmt.Sprintf(keyChannelBanlist, channelKey))
		exceptlistString, _ := tx.Get(fmt.Sprintf(keyChannelExceptlist, channelKey))
		invitelistString, _ := tx.Get(fmt.Sprintf(keyChannelInvitelist, channelKey))
		accountToUModeString, _ := tx.Get(fmt.Sprintf(keyChannelAccountToUMode, channelKey))

		modeSlice := make([]modes.Mode, len(modeString))
		for i, mode := range modeString {
			modeSlice[i] = modes.Mode(mode)
		}

		var banlist []string
		_ = json.Unmarshal([]byte(banlistString), &banlist)
		var exceptlist []string
		_ = json.Unmarshal([]byte(exceptlistString), &exceptlist)
		var invitelist []string
		_ = json.Unmarshal([]byte(invitelistString), &invitelist)
		accountToUMode := make(map[string]modes.Mode)
		_ = json.Unmarshal([]byte(accountToUModeString), &accountToUMode)

		info = &RegisteredChannel{
			Name:           name,
			RegisteredAt:   time.Unix(regTimeInt, 0),
			Founder:        founder,
			Topic:          topic,
			TopicSetBy:     topicSetBy,
			TopicSetTime:   time.Unix(topicSetTimeInt, 0),
			Key:            password,
			Modes:          modeSlice,
			Banlist:        banlist,
			Exceptlist:     exceptlist,
			Invitelist:     invitelist,
			AccountToUMode: accountToUMode,
		}
		return nil
	})

	return info
}

func (reg *ChannelRegistry) Delete(casefoldedName string, info RegisteredChannel) {
	if !reg.server.ChannelRegistrationEnabled() {
		return
	}

	reg.Lock()
	defer reg.Unlock()

	reg.server.store.Update(func(tx *buntdb.Tx) error {
		reg.deleteChannel(tx, casefoldedName, info)
		return nil
	})
}

// deleteByAccount is a helper to delete all channel registrations corresponding to a user account.
func (reg *ChannelRegistry) deleteByAccount(cfaccount string, cfchannels []string) {
	for _, cfchannel := range cfchannels {
		info := reg.LoadChannel(cfchannel)
		if info == nil || info.Founder != cfaccount {
			continue
		}
		reg.Delete(cfchannel, *info)
	}
}

// Rename handles the persistence part of a channel rename: the channel is
// persisted under its new name, and the old name is cleaned up if necessary.
func (reg *ChannelRegistry) Rename(channel *Channel, casefoldedOldName string) {
	if !reg.server.ChannelRegistrationEnabled() {
		return
	}

	reg.Lock()
	defer reg.Unlock()

	includeFlags := IncludeAllChannelAttrs
	oldKey := casefoldedOldName
	key := channel.NameCasefolded()
	info := channel.ExportRegistration(includeFlags)
	if info.Founder == "" {
		return
	}

	reg.server.store.Update(func(tx *buntdb.Tx) error {
		reg.deleteChannel(tx, oldKey, info)
		reg.saveChannel(tx, key, info, includeFlags)
		return nil
	})
}

// delete a channel, unless it was overwritten by another registration of the same channel
func (reg *ChannelRegistry) deleteChannel(tx *buntdb.Tx, key string, info RegisteredChannel) {
	_, err := tx.Get(fmt.Sprintf(keyChannelExists, key))
	if err == nil {
		regTime, _ := tx.Get(fmt.Sprintf(keyChannelRegTime, key))
		regTimeInt, _ := strconv.ParseInt(regTime, 10, 64)
		registeredAt := time.Unix(regTimeInt, 0)
		founder, _ := tx.Get(fmt.Sprintf(keyChannelFounder, key))

		// to see if we're deleting the right channel, confirm the founder and the registration time
		if founder == info.Founder && registeredAt.Unix() == info.RegisteredAt.Unix() {
			for _, keyFmt := range channelKeyStrings {
				tx.Delete(fmt.Sprintf(keyFmt, key))
			}

			// remove this channel from the client's list of registered channels
			channelsKey := fmt.Sprintf(keyAccountChannels, info.Founder)
			channelsStr, err := tx.Get(channelsKey)
			if err == buntdb.ErrNotFound {
				return
			}
			registeredChannels := unmarshalRegisteredChannels(channelsStr)
			var nowRegisteredChannels []string
			for _, channel := range registeredChannels {
				if channel != key {
					nowRegisteredChannels = append(nowRegisteredChannels, channel)
				}
			}
			tx.Set(channelsKey, strings.Join(nowRegisteredChannels, ","), nil)
		}
	}
}

// saveChannel saves a channel to the store.
func (reg *ChannelRegistry) saveChannel(tx *buntdb.Tx, channelKey string, channelInfo RegisteredChannel, includeFlags uint) {
	// maintain the mapping of account -> registered channels
	chanExistsKey := fmt.Sprintf(keyChannelExists, channelKey)
	_, existsErr := tx.Get(chanExistsKey)
	if existsErr == buntdb.ErrNotFound {
		// this is a new registration, need to update account-to-channels
		accountChannelsKey := fmt.Sprintf(keyAccountChannels, channelInfo.Founder)
		alreadyChannels, _ := tx.Get(accountChannelsKey)
		newChannels := channelKey // this is the casefolded channel name
		if alreadyChannels != "" {
			newChannels = fmt.Sprintf("%s,%s", alreadyChannels, newChannels)
		}
		tx.Set(accountChannelsKey, newChannels, nil)
	}

	if includeFlags&IncludeInitial != 0 {
		tx.Set(chanExistsKey, "1", nil)
		tx.Set(fmt.Sprintf(keyChannelName, channelKey), channelInfo.Name, nil)
		tx.Set(fmt.Sprintf(keyChannelRegTime, channelKey), strconv.FormatInt(channelInfo.RegisteredAt.Unix(), 10), nil)
		tx.Set(fmt.Sprintf(keyChannelFounder, channelKey), channelInfo.Founder, nil)
	}

	if includeFlags&IncludeTopic != 0 {
		tx.Set(fmt.Sprintf(keyChannelTopic, channelKey), channelInfo.Topic, nil)
		tx.Set(fmt.Sprintf(keyChannelTopicSetTime, channelKey), strconv.FormatInt(channelInfo.TopicSetTime.Unix(), 10), nil)
		tx.Set(fmt.Sprintf(keyChannelTopicSetBy, channelKey), channelInfo.TopicSetBy, nil)
	}

	if includeFlags&IncludeModes != 0 {
		tx.Set(fmt.Sprintf(keyChannelPassword, channelKey), channelInfo.Key, nil)
		modeStrings := make([]string, len(channelInfo.Modes))
		for i, mode := range channelInfo.Modes {
			modeStrings[i] = string(mode)
		}
		tx.Set(fmt.Sprintf(keyChannelModes, channelKey), strings.Join(modeStrings, ""), nil)
	}

	if includeFlags&IncludeLists != 0 {
		banlistString, _ := json.Marshal(channelInfo.Banlist)
		tx.Set(fmt.Sprintf(keyChannelBanlist, channelKey), string(banlistString), nil)
		exceptlistString, _ := json.Marshal(channelInfo.Exceptlist)
		tx.Set(fmt.Sprintf(keyChannelExceptlist, channelKey), string(exceptlistString), nil)
		invitelistString, _ := json.Marshal(channelInfo.Invitelist)
		tx.Set(fmt.Sprintf(keyChannelInvitelist, channelKey), string(invitelistString), nil)
		accountToUModeString, _ := json.Marshal(channelInfo.AccountToUMode)
		tx.Set(fmt.Sprintf(keyChannelAccountToUMode, channelKey), string(accountToUModeString), nil)
	}
}
