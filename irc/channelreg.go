// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"encoding/json"

	"github.com/tidwall/buntdb"
)

// this is exclusively the *persistence* layer for channel registration;
// channel creation/tracking/destruction is in channelmanager.go

const (
	keyChannelExists       = "channel.exists %s"
	keyChannelName         = "channel.name %s" // stores the 'preferred name' of the channel, not casemapped
	keyChannelRegTime      = "channel.registered.time %s"
	keyChannelFounder      = "channel.founder %s"
	keyChannelTopic        = "channel.topic %s"
	keyChannelTopicSetBy   = "channel.topic.setby %s"
	keyChannelTopicSetTime = "channel.topic.settime %s"
	keyChannelBanlist      = "channel.banlist %s"
	keyChannelExceptlist   = "channel.exceptlist %s"
	keyChannelInvitelist   = "channel.invitelist %s"
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
	}
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
	// Banlist represents the bans set on the channel.
	Banlist []string
	// Exceptlist represents the exceptions set on the channel.
	Exceptlist []string
	// Invitelist represents the invite exceptions set on the channel.
	Invitelist []string
}

type ChannelRegistry struct {
	// this serializes operations of the form (read channel state, synchronously persist it);
	// this is enough to guarantee eventual consistency of the database with the
	// ChannelManager and Channel objects, which are the source of truth.
	// Wwe could use the buntdb RW transaction lock for this purpose but we share
	// that with all the other modules, so let's not.
	sync.Mutex // tier 2
	server     *Server
}

func NewChannelRegistry(server *Server) *ChannelRegistry {
	return &ChannelRegistry{
		server: server,
	}
}

// StoreChannel obtains a consistent view of a channel, then persists it to the store.
func (reg *ChannelRegistry) StoreChannel(channel *Channel, includeLists bool) {
	if !reg.server.ChannelRegistrationEnabled() {
		return
	}

	reg.Lock()
	defer reg.Unlock()

	key := channel.NameCasefolded()
	info := channel.ExportRegistration(includeLists)
	if info.Founder == "" {
		// sanity check, don't try to store an unregistered channel
		return
	}

	reg.server.store.Update(func(tx *buntdb.Tx) error {
		reg.saveChannel(tx, key, info, includeLists)
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
		banlistString, _ := tx.Get(fmt.Sprintf(keyChannelBanlist, channelKey))
		exceptlistString, _ := tx.Get(fmt.Sprintf(keyChannelExceptlist, channelKey))
		invitelistString, _ := tx.Get(fmt.Sprintf(keyChannelInvitelist, channelKey))

		var banlist []string
		_ = json.Unmarshal([]byte(banlistString), &banlist)
		var exceptlist []string
		_ = json.Unmarshal([]byte(exceptlistString), &exceptlist)
		var invitelist []string
		_ = json.Unmarshal([]byte(invitelistString), &invitelist)

		info = &RegisteredChannel{
			Name:         name,
			RegisteredAt: time.Unix(regTimeInt, 0),
			Founder:      founder,
			Topic:        topic,
			TopicSetBy:   topicSetBy,
			TopicSetTime: time.Unix(topicSetTimeInt, 0),
			Banlist:      banlist,
			Exceptlist:   exceptlist,
			Invitelist:   invitelist,
		}
		return nil
	})

	return info
}

// Rename handles the persistence part of a channel rename: the channel is
// persisted under its new name, and the old name is cleaned up if necessary.
func (reg *ChannelRegistry) Rename(channel *Channel, casefoldedOldName string) {
	if !reg.server.ChannelRegistrationEnabled() {
		return
	}

	reg.Lock()
	defer reg.Unlock()

	includeLists := true
	oldKey := casefoldedOldName
	key := channel.NameCasefolded()
	info := channel.ExportRegistration(includeLists)
	if info.Founder == "" {
		return
	}

	reg.server.store.Update(func(tx *buntdb.Tx) error {
		reg.deleteChannel(tx, oldKey, info)
		reg.saveChannel(tx, key, info, includeLists)
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
		if founder == info.Founder && registeredAt == info.RegisteredAt {
			for _, keyFmt := range channelKeyStrings {
				tx.Delete(fmt.Sprintf(keyFmt, key))
			}
		}
	}
}

// saveChannel saves a channel to the store.
func (reg *ChannelRegistry) saveChannel(tx *buntdb.Tx, channelKey string, channelInfo RegisteredChannel, includeLists bool) {
	tx.Set(fmt.Sprintf(keyChannelExists, channelKey), "1", nil)
	tx.Set(fmt.Sprintf(keyChannelName, channelKey), channelInfo.Name, nil)
	tx.Set(fmt.Sprintf(keyChannelRegTime, channelKey), strconv.FormatInt(channelInfo.RegisteredAt.Unix(), 10), nil)
	tx.Set(fmt.Sprintf(keyChannelFounder, channelKey), channelInfo.Founder, nil)
	tx.Set(fmt.Sprintf(keyChannelTopic, channelKey), channelInfo.Topic, nil)
	tx.Set(fmt.Sprintf(keyChannelTopicSetBy, channelKey), channelInfo.TopicSetBy, nil)
	tx.Set(fmt.Sprintf(keyChannelTopicSetTime, channelKey), strconv.FormatInt(channelInfo.TopicSetTime.Unix(), 10), nil)

	if includeLists {
		banlistString, _ := json.Marshal(channelInfo.Banlist)
		tx.Set(fmt.Sprintf(keyChannelBanlist, channelKey), string(banlistString), nil)
		exceptlistString, _ := json.Marshal(channelInfo.Exceptlist)
		tx.Set(fmt.Sprintf(keyChannelExceptlist, channelKey), string(exceptlistString), nil)
		invitelistString, _ := json.Marshal(channelInfo.Invitelist)
		tx.Set(fmt.Sprintf(keyChannelInvitelist, channelKey), string(invitelistString), nil)
	}
}
