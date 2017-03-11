// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"strconv"
	"time"

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

	chanInfo := RegisteredChannel{
		Name:         name,
		RegisteredAt: time.Unix(regTimeInt, 0),
		Founder:      founder,
		Topic:        topic,
		TopicSetBy:   topicSetBy,
		TopicSetTime: time.Unix(topicSetTimeInt, 0),
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
	server.registeredChannels[channelKey] = &channelInfo
}
