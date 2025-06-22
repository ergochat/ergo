package irc

import (
	"errors"
	"iter"
	"maps"
	"regexp"
	"unicode/utf8"

	"github.com/ergochat/ergo/irc/caps"
	"github.com/ergochat/ergo/irc/modes"
)

const (
	// metadata key + value need to be relayable on a single IRC RPL_KEYVALUE line
	maxCombinedMetadataLenBytes = 350
)

var (
	errMetadataTooManySubs = errors.New("too many subscriptions")
	errMetadataNotFound    = errors.New("key not found")
)

type MetadataHaver = interface {
	SetMetadata(key string, value string, limit int) (updated bool, err error)
	GetMetadata(key string) (string, bool)
	DeleteMetadata(key string) (updated bool)
	ListMetadata() map[string]string
	ClearMetadata() map[string]string
	CountMetadata() int
}

func notifySubscribers(server *Server, session *Session, targetObj MetadataHaver, targetName, key, value string, set bool) {
	var recipientSessions iter.Seq[*Session]

	switch target := targetObj.(type) {
	case *Client:
		// TODO this case is expensive and might warrant rate-limiting
		friends := target.FriendsMonitors(caps.Metadata)
		// broadcast metadata update to other connected sessions
		for _, s := range target.Sessions() {
			friends.Add(s)
		}
		recipientSessions = maps.Keys(friends)
	case *Channel:
		recipientSessions = target.sessionsWithCaps(caps.Metadata)
	default:
		return // impossible
	}

	broadcastMetadataUpdate(server, recipientSessions, session, targetName, key, value, set)
}

func broadcastMetadataUpdate(server *Server, sessions iter.Seq[*Session], originator *Session, target, key, value string, set bool) {
	for s := range sessions {
		// don't notify the session that made the change
		if s == originator || !s.isSubscribedTo(key) {
			continue
		}

		if set {
			s.Send(nil, server.name, "METADATA", target, key, "*", value)
		} else {
			s.Send(nil, server.name, "METADATA", target, key, "*")
		}
	}
}

func syncClientMetadata(server *Server, rb *ResponseBuffer, target *Client) {
	batchId := rb.StartNestedBatch("metadata", target.Nick())
	defer rb.EndNestedBatch(batchId)

	subs := rb.session.MetadataSubscriptions()
	values := target.ListMetadata()
	for k, v := range values {
		if subs.Has(k) {
			visibility := "*"
			rb.Add(nil, server.name, "METADATA", target.Nick(), k, visibility, v)
		}
	}
}

func syncChannelMetadata(server *Server, rb *ResponseBuffer, channel *Channel) {
	batchId := rb.StartNestedBatch("metadata", channel.Name())
	defer rb.EndNestedBatch(batchId)

	subs := rb.session.MetadataSubscriptions()
	chname := channel.Name()

	values := channel.ListMetadata()
	for k, v := range values {
		if subs.Has(k) {
			visibility := "*"
			rb.Add(nil, server.name, "METADATA", chname, k, visibility, v)
		}
	}

	for _, client := range channel.Members() {
		values := client.ListMetadata()
		for k, v := range values {
			if subs.Has(k) {
				visibility := "*"
				rb.Add(nil, server.name, "METADATA", client.Nick(), k, visibility, v)
			}
		}
	}
}

func playMetadataList(rb *ResponseBuffer, nick, target string, values map[string]string) {
	batchId := rb.StartNestedBatch("metadata", target)
	defer rb.EndNestedBatch(batchId)

	for key, val := range values {
		visibility := "*"
		rb.Add(nil, rb.session.client.server.name, RPL_KEYVALUE, nick, target, key, visibility, val)
	}
}

func playMetadataVerbBatch(rb *ResponseBuffer, target string, values map[string]string) {
	batchId := rb.StartNestedBatch("metadata", target)
	defer rb.EndNestedBatch(batchId)

	for key, val := range values {
		visibility := "*"
		rb.Add(nil, rb.session.client.server.name, "METADATA", target, key, visibility, val)
	}
}

var validMetadataKeyRegexp = regexp.MustCompile("^[a-z0-9_./-]+$")

func metadataKeyIsEvil(key string) bool {
	return !validMetadataKeyRegexp.MatchString(key)
}

func metadataValueIsEvil(config *Config, key, value string) (failMsg string) {
	if !globalUtf8EnforcementSetting && !utf8.ValidString(value) {
		return `METADATA values must be UTF-8`
	}

	if len(key)+len(value) > maxCombinedMetadataLenBytes ||
		(config.Metadata.MaxValueBytes > 0 && len(value) > config.Metadata.MaxValueBytes) {

		return `Value is too long`
	}

	return "" // success
}

func metadataCanIEditThisKey(client *Client, targetObj MetadataHaver, key string) bool {
	// no key-specific logic as yet
	return metadataCanIEditThisTarget(client, targetObj)
}

func metadataCanIEditThisTarget(client *Client, targetObj MetadataHaver) bool {
	switch target := targetObj.(type) {
	case *Client:
		return client == target || client.HasRoleCapabs("metadata")
	case *Channel:
		return target.ClientIsAtLeast(client, modes.Operator) || client.HasRoleCapabs("metadata")
	default:
		return false // impossible
	}
}

func metadataCanISeeThisTarget(client *Client, targetObj MetadataHaver) bool {
	switch target := targetObj.(type) {
	case *Client:
		return true
	case *Channel:
		return target.hasClient(client) || client.HasRoleCapabs("metadata")
	default:
		return false // impossible
	}
}
