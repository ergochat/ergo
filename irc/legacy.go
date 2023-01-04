// Copyright (c) 2018 Shivaram Lingamneni

package irc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/tidwall/buntdb"

	"github.com/ergochat/ergo/irc/modes"
)

var (
	errInvalidPasswordHash = errors.New("invalid password hash")
)

// Decode a hashed passphrase as it would appear in a config file,
// retaining compatibility with old versions of `oragono genpasswd`
// that used to apply a redundant layer of base64
func decodeLegacyPasswordHash(hash string) ([]byte, error) {
	// a correctly formatted bcrypt hash is 60 bytes of printable ASCII
	if len(hash) == 80 {
		// double-base64, remove the outer layer:
		return base64.StdEncoding.DecodeString(hash)
	} else if len(hash) == 60 {
		return []byte(hash), nil
	} else {
		return nil, errInvalidPasswordHash
	}
}

// legacy channel registration code

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

func deleteLegacyChannel(tx *buntdb.Tx, nameCasefolded string) {
	tx.Delete(fmt.Sprintf(keyChannelExists, nameCasefolded))
	tx.Delete(fmt.Sprintf(keyChannelName, nameCasefolded))
	tx.Delete(fmt.Sprintf(keyChannelRegTime, nameCasefolded))
	tx.Delete(fmt.Sprintf(keyChannelFounder, nameCasefolded))
	tx.Delete(fmt.Sprintf(keyChannelTopic, nameCasefolded))
	tx.Delete(fmt.Sprintf(keyChannelTopicSetBy, nameCasefolded))
	tx.Delete(fmt.Sprintf(keyChannelTopicSetTime, nameCasefolded))
	tx.Delete(fmt.Sprintf(keyChannelBanlist, nameCasefolded))
	tx.Delete(fmt.Sprintf(keyChannelExceptlist, nameCasefolded))
	tx.Delete(fmt.Sprintf(keyChannelInvitelist, nameCasefolded))
	tx.Delete(fmt.Sprintf(keyChannelPassword, nameCasefolded))
	tx.Delete(fmt.Sprintf(keyChannelModes, nameCasefolded))
	tx.Delete(fmt.Sprintf(keyChannelAccountToUMode, nameCasefolded))
	tx.Delete(fmt.Sprintf(keyChannelUserLimit, nameCasefolded))
	tx.Delete(fmt.Sprintf(keyChannelSettings, nameCasefolded))
	tx.Delete(fmt.Sprintf(keyChannelForward, nameCasefolded))
}

func loadLegacyChannel(tx *buntdb.Tx, nameCasefolded string) (info RegisteredChannel, err error) {
	channelKey := nameCasefolded
	// nice to have: do all JSON (de)serialization outside of the buntdb transaction
	_, dberr := tx.Get(fmt.Sprintf(keyChannelExists, channelKey))
	if dberr == buntdb.ErrNotFound {
		// chan does not already exist, return
		err = errNoSuchChannel
		return
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
	return info, nil
}
