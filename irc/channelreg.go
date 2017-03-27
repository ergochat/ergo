// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"encoding/json"

	"github.com/tidwall/buntdb"
)

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
	errChanExists = errors.New("Channel already exists")
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

// loadChannelNoMutex loads a channel from the store.
func (server *Server) loadChannelNoMutex(tx *buntdb.Tx, channelKey string) *RegisteredChannel {
	// return loaded chan if it already exists
	if server.registeredChannels[channelKey] != nil {
		return server.registeredChannels[channelKey]
	}
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

	chanInfo := RegisteredChannel{
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
	server.registeredChannels[channelKey] = &chanInfo

	return &chanInfo
}

// saveChannelNoMutex saves a channel to the store.
func (server *Server) saveChannelNoMutex(tx *buntdb.Tx, channelKey string, channelInfo RegisteredChannel) {
	tx.Set(fmt.Sprintf(keyChannelExists, channelKey), "1", nil)
	tx.Set(fmt.Sprintf(keyChannelName, channelKey), channelInfo.Name, nil)
	tx.Set(fmt.Sprintf(keyChannelRegTime, channelKey), strconv.FormatInt(channelInfo.RegisteredAt.Unix(), 10), nil)
	tx.Set(fmt.Sprintf(keyChannelFounder, channelKey), channelInfo.Founder, nil)
	tx.Set(fmt.Sprintf(keyChannelTopic, channelKey), channelInfo.Topic, nil)
	tx.Set(fmt.Sprintf(keyChannelTopicSetBy, channelKey), channelInfo.TopicSetBy, nil)
	tx.Set(fmt.Sprintf(keyChannelTopicSetTime, channelKey), strconv.FormatInt(channelInfo.TopicSetTime.Unix(), 10), nil)

	banlistString, _ := json.Marshal(channelInfo.Banlist)
	tx.Set(fmt.Sprintf(keyChannelBanlist, channelKey), string(banlistString), nil)
	exceptlistString, _ := json.Marshal(channelInfo.Exceptlist)
	tx.Set(fmt.Sprintf(keyChannelExceptlist, channelKey), string(exceptlistString), nil)
	invitelistString, _ := json.Marshal(channelInfo.Invitelist)
	tx.Set(fmt.Sprintf(keyChannelInvitelist, channelKey), string(invitelistString), nil)

	server.registeredChannels[channelKey] = &channelInfo
}
