package irc

import (
	"errors"
	"regexp"
	"strings"

	"github.com/ergochat/ergo/irc/caps"
	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/utils"
)

var (
	errMetadataTooManySubs = errors.New("too many subscriptions")
	errMetadataNotFound    = errors.New("key not found")
)

type MetadataStore = map[string]string

type MetadataHaver = interface {
	SetMetadata(key string, value string)
	GetMetadata(key string) (string, error)
	DeleteMetadata(key string)
	ListMetadata() MetadataStore
	ClearMetadata() MetadataStore
}

func notifySubscribers(server *Server, session *Session, target string, key string, value string) {
	var notify utils.HashSet[*Session] = make(utils.HashSet[*Session])
	targetChannel := server.channels.Get(target)
	targetClient := server.clients.Get(target)

	if targetClient != nil {
		notify = targetClient.FriendsMonitors(caps.MetadataTwoJudgementDay)
		// notify clients about changes regarding themselves
		for _, s := range targetClient.Sessions() {
			notify.Add(s)
		}
	}
	if targetChannel != nil {
		members := targetChannel.Members()
		for _, m := range members {
			for _, s := range m.Sessions() {
				if s.capabilities.Has(caps.MetadataTwoJudgementDay) {
					notify.Add(s)
				}
			}
		}
	}

	// don't notify the session that made the change
	notify.Remove(session)

	for s := range notify {
		if !s.isSubscribedTo(key) {
			continue
		}

		if value != "" {
			s.Send(nil, server.name, "METADATA", target, key, "*", value)
		} else {
			s.Send(nil, server.name, "METADATA", target, key, "*")
		}
	}
}

var metadataEvilCharsRegexp = regexp.MustCompile("[^A-Za-z0-9_./:-]+")

func metadataKeyIsEvil(key string) bool {
	key = strings.TrimSpace(key) // just in case

	return len(key) == 0 || // key needs to contain stuff
		key[0] == ':' || // key can't start with a colon
		metadataEvilCharsRegexp.MatchString(key) // key can't contain the stuff it can't contain
}

func metadataCanIEditThisKey(client *Client, target string, _ string) bool {
	if !metadataCanIEditThisTarget(client, target) { // you can't edit keys on targets you can't edit.
		return false
	}

	// todo: we don't actually do anything regarding visibility yet so there's not much to do here

	return true
}

func metadataCanIEditThisTarget(client *Client, target string) bool {
	if !metadataCanISeeThisTarget(client, target) { // you can't edit what you can't see. a wise man told me this once
		return false
	}

	if client.HasRoleCapabs("sajoin") { // sajoin opers can do whatever they want
		return true
	}

	if target == client.Nick() { // your right to swing your fist ends where my nose begins
		return true
	}

	// if you're a channel operator, knock yourself out
	channel := client.server.channels.Get(target)
	if channel != nil && channel.ClientIsAtLeast(client, modes.Operator) {
		return true
	}

	return false
}

func metadataCanISeeThisTarget(client *Client, target string) bool {
	if client.HasRoleCapabs("sajoin") { // sajoin opers can do whatever they want
		return true
	}

	// check if the user is in the channel
	channel := client.server.channels.Get(target)
	if channel != nil && !channel.hasClient(client) {
		return false
	}

	return true
}
