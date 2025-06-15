package irc

import (
	"errors"
	"iter"
	"maps"
	"regexp"
	"strings"

	"github.com/ergochat/ergo/irc/caps"
	"github.com/ergochat/ergo/irc/modes"
)

var (
	errMetadataTooManySubs = errors.New("too many subscriptions")
	errMetadataNotFound    = errors.New("key not found")
)

type MetadataHaver = interface {
	SetMetadata(key string, value string)
	GetMetadata(key string) (string, bool)
	DeleteMetadata(key string)
	ListMetadata() map[string]string
	ClearMetadata() map[string]string
	CountMetadata() int
}

func notifySubscribers(server *Server, session *Session, targetObj MetadataHaver, targetName, key, value string) {
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
		recipientSessions = target.sessionsWithCap(caps.Metadata)
	default:
		return // impossible
	}

	broadcastMetadataUpdate(server, recipientSessions, session, targetName, key, value)
}

func broadcastMetadataUpdate(server *Server, sessions iter.Seq[*Session], originator *Session, target, key, value string) {
	for s := range sessions {
		// don't notify the session that made the change
		if s == originator || !s.isSubscribedTo(key) {
			continue
		}

		if value != "" {
			s.Send(nil, server.name, "METADATA", target, key, "*", value)
		} else {
			s.Send(nil, server.name, "METADATA", target, key, "*")
		}
	}
}

func syncClientMetadata(server *Server, rb *ResponseBuffer, target *Client) {
	if len(rb.session.MetadataSubscriptions()) == 0 {
		return
	}

	batchId := rb.StartNestedBatch("metadata")
	defer rb.EndNestedBatch(batchId)

	values := target.ListMetadata()
	for k, v := range values {
		if rb.session.isSubscribedTo(k) {
			visibility := "*"
			rb.Add(nil, server.name, "METADATA", target.Nick(), k, visibility, v)
		}
	}
}

func syncChannelMetadata(server *Server, rb *ResponseBuffer, target *Channel) {
	if len(rb.session.MetadataSubscriptions()) == 0 {
		return
	}

	batchId := rb.StartNestedBatch("metadata")
	defer rb.EndNestedBatch(batchId)

	values := target.ListMetadata()
	for k, v := range values {
		if rb.session.isSubscribedTo(k) {
			visibility := "*"
			rb.Add(nil, server.name, "METADATA", target.Name(), k, visibility, v)
		}
	}

	for _, client := range target.Members() {
		values := client.ListMetadata()
		for k, v := range values {
			if rb.session.isSubscribedTo(k) {
				visibility := "*"
				rb.Add(nil, server.name, "METADATA", client.Nick(), k, visibility, v)
			}
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
