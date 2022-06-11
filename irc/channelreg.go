// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/buntdb"

	"github.com/ergochat/ergo/irc/kv"
	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/utils"
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
	keyChannelUserLimit      = "channel.userlimit %s"
	keyChannelSettings       = "channel.settings %s"
	keyChannelForward        = "channel.forward %s"

	keyChannelPurged = "channel.purged %s"
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
		keyChannelUserLimit,
		keyChannelSettings,
		keyChannelForward,
	}
)

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
	// Casefolded name of the channel.
	NameCasefolded string
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
}

type ChannelPurgeRecord struct {
	Oper     string
	PurgedAt time.Time
	Reason   string
}

// ChannelRegistry manages registered channels.
type ChannelRegistry struct {
	server *Server
}

// NewChannelRegistry returns a new ChannelRegistry.
func (reg *ChannelRegistry) Initialize(server *Server) {
	reg.server = server
}

// AllChannels returns the uncasefolded names of all registered channels.
func (reg *ChannelRegistry) AllChannels() (result []string) {
	prefix := fmt.Sprintf(keyChannelName, "")
	reg.server.store.View(func(tx kv.Tx) error {
		return tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
			if !strings.HasPrefix(key, prefix) {
				return false
			}
			result = append(result, value)
			return true
		})
	})

	return
}

// PurgedChannels returns the set of all casefolded channel names that have been purged
func (reg *ChannelRegistry) PurgedChannels() (result utils.HashSet[string]) {
	result = make(utils.HashSet[string])

	prefix := fmt.Sprintf(keyChannelPurged, "")
	reg.server.store.View(func(tx kv.Tx) error {
		return tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
			if !strings.HasPrefix(key, prefix) {
				return false
			}
			channel := strings.TrimPrefix(key, prefix)
			result.Add(channel)
			return true
		})
	})
	return
}

// StoreChannel obtains a consistent view of a channel, then persists it to the store.
func (reg *ChannelRegistry) StoreChannel(info RegisteredChannel, includeFlags uint) (err error) {
	if !reg.server.ChannelRegistrationEnabled() {
		return
	}

	if info.Founder == "" {
		// sanity check, don't try to store an unregistered channel
		return
	}

	reg.server.store.Update(func(tx kv.Tx) error {
		reg.saveChannel(tx, info, includeFlags)
		return nil
	})

	return nil
}

// LoadChannel loads a channel from the store.
func (reg *ChannelRegistry) LoadChannel(nameCasefolded string) (info RegisteredChannel, err error) {
	if !reg.server.ChannelRegistrationEnabled() {
		err = errFeatureDisabled
		return
	}

	channelKey := nameCasefolded
	// nice to have: do all JSON (de)serialization outside of the buntdb transaction
	err = reg.server.store.View(func(tx kv.Tx) error {
		_, dberr := tx.Get(fmt.Sprintf(keyChannelExists, channelKey))
		if dberr == buntdb.ErrNotFound {
			// chan does not already exist, return
			return errNoSuchChannel
		}

		// channel exists, load it
		name, _ := tx.Get(fmt.Sprintf(keyChannelName, channelKey))
		regTime, _ := tx.Get(fmt.Sprintf(keyChannelRegTime, channelKey))
		regTimeInt, _ := strconv.ParseInt(regTime, 10, 64)
		founder, _ := tx.Get(fmt.Sprintf(keyChannelFounder, channelKey))
		topic, _ := tx.Get(fmt.Sprintf(keyChannelTopic, channelKey))
		topicSetBy, _ := tx.Get(fmt.Sprintf(keyChannelTopicSetBy, channelKey))
		var topicSetTime time.Time
		topicSetTimeStr, _ := tx.Get(fmt.Sprintf(keyChannelTopicSetTime, channelKey))
		if topicSetTimeInt, topicSetTimeErr := strconv.ParseInt(topicSetTimeStr, 10, 64); topicSetTimeErr == nil {
			topicSetTime = time.Unix(0, topicSetTimeInt).UTC()
		}
		password, _ := tx.Get(fmt.Sprintf(keyChannelPassword, channelKey))
		modeString, _ := tx.Get(fmt.Sprintf(keyChannelModes, channelKey))
		userLimitString, _ := tx.Get(fmt.Sprintf(keyChannelUserLimit, channelKey))
		forward, _ := tx.Get(fmt.Sprintf(keyChannelForward, channelKey))
		banlistString, _ := tx.Get(fmt.Sprintf(keyChannelBanlist, channelKey))
		exceptlistString, _ := tx.Get(fmt.Sprintf(keyChannelExceptlist, channelKey))
		invitelistString, _ := tx.Get(fmt.Sprintf(keyChannelInvitelist, channelKey))
		accountToUModeString, _ := tx.Get(fmt.Sprintf(keyChannelAccountToUMode, channelKey))
		settingsString, _ := tx.Get(fmt.Sprintf(keyChannelSettings, channelKey))

		modeSlice := make([]modes.Mode, len(modeString))
		for i, mode := range modeString {
			modeSlice[i] = modes.Mode(mode)
		}

		userLimit, _ := strconv.Atoi(userLimitString)

		var banlist map[string]MaskInfo
		_ = json.Unmarshal([]byte(banlistString), &banlist)
		var exceptlist map[string]MaskInfo
		_ = json.Unmarshal([]byte(exceptlistString), &exceptlist)
		var invitelist map[string]MaskInfo
		_ = json.Unmarshal([]byte(invitelistString), &invitelist)
		accountToUMode := make(map[string]modes.Mode)
		_ = json.Unmarshal([]byte(accountToUModeString), &accountToUMode)

		var settings ChannelSettings
		_ = json.Unmarshal([]byte(settingsString), &settings)

		info = RegisteredChannel{
			Name:           name,
			NameCasefolded: nameCasefolded,
			RegisteredAt:   time.Unix(0, regTimeInt).UTC(),
			Founder:        founder,
			Topic:          topic,
			TopicSetBy:     topicSetBy,
			TopicSetTime:   topicSetTime,
			Key:            password,
			Modes:          modeSlice,
			Bans:           banlist,
			Excepts:        exceptlist,
			Invites:        invitelist,
			AccountToUMode: accountToUMode,
			UserLimit:      int(userLimit),
			Settings:       settings,
			Forward:        forward,
		}
		return nil
	})

	return
}

// Delete deletes a channel corresponding to `info`. If no such channel
// is present in the database, no error is returned.
func (reg *ChannelRegistry) Delete(info RegisteredChannel) (err error) {
	if !reg.server.ChannelRegistrationEnabled() {
		return
	}

	reg.server.store.Update(func(tx kv.Tx) error {
		reg.deleteChannel(tx, info.NameCasefolded, info)
		return nil
	})
	return nil
}

// delete a channel, unless it was overwritten by another registration of the same channel
func (reg *ChannelRegistry) deleteChannel(tx kv.Tx, key string, info RegisteredChannel) {
	_, err := tx.Get(fmt.Sprintf(keyChannelExists, key))
	if err == nil {
		regTime, _ := tx.Get(fmt.Sprintf(keyChannelRegTime, key))
		regTimeInt, _ := strconv.ParseInt(regTime, 10, 64)
		registeredAt := time.Unix(0, regTimeInt).UTC()
		founder, _ := tx.Get(fmt.Sprintf(keyChannelFounder, key))

		// to see if we're deleting the right channel, confirm the founder and the registration time
		if founder == info.Founder && registeredAt.Equal(info.RegisteredAt) {
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

func (reg *ChannelRegistry) updateAccountToChannelMapping(tx kv.Tx, channelInfo RegisteredChannel) {
	channelKey := channelInfo.NameCasefolded
	chanFounderKey := fmt.Sprintf(keyChannelFounder, channelKey)
	founder, existsErr := tx.Get(chanFounderKey)
	if existsErr == buntdb.ErrNotFound || founder != channelInfo.Founder {
		// add to new founder's list
		accountChannelsKey := fmt.Sprintf(keyAccountChannels, channelInfo.Founder)
		alreadyChannels, _ := tx.Get(accountChannelsKey)
		newChannels := channelKey // this is the casefolded channel name
		if alreadyChannels != "" {
			newChannels = fmt.Sprintf("%s,%s", alreadyChannels, newChannels)
		}
		tx.Set(accountChannelsKey, newChannels, nil)
	}
	if existsErr == nil && founder != channelInfo.Founder {
		// remove from old founder's list
		accountChannelsKey := fmt.Sprintf(keyAccountChannels, founder)
		alreadyChannelsRaw, _ := tx.Get(accountChannelsKey)
		var newChannels []string
		if alreadyChannelsRaw != "" {
			for _, chname := range strings.Split(alreadyChannelsRaw, ",") {
				if chname != channelInfo.NameCasefolded {
					newChannels = append(newChannels, chname)
				}
			}
		}
		tx.Set(accountChannelsKey, strings.Join(newChannels, ","), nil)
	}
}

// saveChannel saves a channel to the store.
func (reg *ChannelRegistry) saveChannel(tx kv.Tx, channelInfo RegisteredChannel, includeFlags uint) {
	channelKey := channelInfo.NameCasefolded
	// maintain the mapping of account -> registered channels
	reg.updateAccountToChannelMapping(tx, channelInfo)

	if includeFlags&IncludeInitial != 0 {
		tx.Set(fmt.Sprintf(keyChannelExists, channelKey), "1", nil)
		tx.Set(fmt.Sprintf(keyChannelName, channelKey), channelInfo.Name, nil)
		tx.Set(fmt.Sprintf(keyChannelRegTime, channelKey), strconv.FormatInt(channelInfo.RegisteredAt.UnixNano(), 10), nil)
		tx.Set(fmt.Sprintf(keyChannelFounder, channelKey), channelInfo.Founder, nil)
	}

	if includeFlags&IncludeTopic != 0 {
		tx.Set(fmt.Sprintf(keyChannelTopic, channelKey), channelInfo.Topic, nil)
		var topicSetTimeStr string
		if !channelInfo.TopicSetTime.IsZero() {
			topicSetTimeStr = strconv.FormatInt(channelInfo.TopicSetTime.UnixNano(), 10)
		}
		tx.Set(fmt.Sprintf(keyChannelTopicSetTime, channelKey), topicSetTimeStr, nil)
		tx.Set(fmt.Sprintf(keyChannelTopicSetBy, channelKey), channelInfo.TopicSetBy, nil)
	}

	if includeFlags&IncludeModes != 0 {
		tx.Set(fmt.Sprintf(keyChannelPassword, channelKey), channelInfo.Key, nil)
		modeString := modes.Modes(channelInfo.Modes).String()
		tx.Set(fmt.Sprintf(keyChannelModes, channelKey), modeString, nil)
		tx.Set(fmt.Sprintf(keyChannelUserLimit, channelKey), strconv.Itoa(channelInfo.UserLimit), nil)
		tx.Set(fmt.Sprintf(keyChannelForward, channelKey), channelInfo.Forward, nil)
	}

	if includeFlags&IncludeLists != 0 {
		banlistString, _ := json.Marshal(channelInfo.Bans)
		tx.Set(fmt.Sprintf(keyChannelBanlist, channelKey), string(banlistString), nil)
		exceptlistString, _ := json.Marshal(channelInfo.Excepts)
		tx.Set(fmt.Sprintf(keyChannelExceptlist, channelKey), string(exceptlistString), nil)
		invitelistString, _ := json.Marshal(channelInfo.Invites)
		tx.Set(fmt.Sprintf(keyChannelInvitelist, channelKey), string(invitelistString), nil)
		accountToUModeString, _ := json.Marshal(channelInfo.AccountToUMode)
		tx.Set(fmt.Sprintf(keyChannelAccountToUMode, channelKey), string(accountToUModeString), nil)
	}

	if includeFlags&IncludeSettings != 0 {
		settingsString, _ := json.Marshal(channelInfo.Settings)
		tx.Set(fmt.Sprintf(keyChannelSettings, channelKey), string(settingsString), nil)
	}
}

// PurgeChannel records a channel purge.
func (reg *ChannelRegistry) PurgeChannel(chname string, record ChannelPurgeRecord) (err error) {
	serialized, err := json.Marshal(record)
	if err != nil {
		return err
	}
	serializedStr := string(serialized)
	key := fmt.Sprintf(keyChannelPurged, chname)

	return reg.server.store.Update(func(tx kv.Tx) error {
		tx.Set(key, serializedStr, nil)
		return nil
	})
}

// LoadPurgeRecord retrieves information about whether and how a channel was purged.
func (reg *ChannelRegistry) LoadPurgeRecord(chname string) (record ChannelPurgeRecord, err error) {
	var rawRecord string
	key := fmt.Sprintf(keyChannelPurged, chname)
	reg.server.store.View(func(tx kv.Tx) error {
		rawRecord, _ = tx.Get(key)
		return nil
	})
	if rawRecord == "" {
		err = errNoSuchChannel
		return
	}
	err = json.Unmarshal([]byte(rawRecord), &record)
	if err != nil {
		reg.server.logger.Error("internal", "corrupt purge record", chname, err.Error())
		err = errNoSuchChannel
		return
	}
	return
}

// UnpurgeChannel deletes the record of a channel purge.
func (reg *ChannelRegistry) UnpurgeChannel(chname string) (err error) {
	key := fmt.Sprintf(keyChannelPurged, chname)
	return reg.server.store.Update(func(tx kv.Tx) error {
		tx.Delete(key)
		return nil
	})
}
