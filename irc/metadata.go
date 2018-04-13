// Copyright (c) 2018 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"sync"

	"github.com/goshuirc/irc-go/ircmsg"
)

var (
	//TODO(dan): temporary hardcoded limits, make these configurable instead.
	metadataKeysLimit = 20
	metadataSubsLimit = 20
)

// MetadataKeysLimit returns how many metadata keys can be set on each client/channel.
//TODO(dan): have this be configurable in the config file instead.
func (server *Server) MetadataKeysLimit() int {
	return metadataKeysLimit
}

// MetadataSubsLimit returns how many metadata keys can be subscribed to.
//TODO(dan): have this be configurable in the config file instead.
func (server *Server) MetadataSubsLimit() int {
	return metadataSubsLimit
}

// MetadataManager manages metadata for a client or channel.
type MetadataManager struct {
	sync.RWMutex
	// keyvals holds our values internally.
	keyvals map[string]string
}

// NewMetadataManager returns a new MetadataManager.
func NewMetadataManager() *MetadataManager {
	var mm MetadataManager
	mm.keyvals = make(map[string]string)
	return &mm
}

// Clear deletes all keys, returning a list of the deleted keys.
func (mm *MetadataManager) Clear() []string {
	var keys []string

	mm.Lock()
	defer mm.Unlock()

	for key := range mm.keyvals {
		keys = append(keys, key)
		delete(mm.keyvals, key)
	}
	return keys
}

// List returns all keys and values.
func (mm *MetadataManager) List() map[string]string {
	data := make(map[string]string)

	mm.RLock()
	defer mm.RUnlock()

	for key, value := range mm.keyvals {
		data[key] = value
	}
	return data
}

// Get returns the value of a single key.
func (mm *MetadataManager) Get(key string) (string, bool) {
	mm.RLock()
	defer mm.RUnlock()

	value, exists := mm.keyvals[key]
	return value, exists
}

// Set sets the value of the given key. A limit of -1 means ignore any limits.
func (mm *MetadataManager) Set(key, value string, limit int) error {
	mm.Lock()
	defer mm.Unlock()

	_, currentlyExists := mm.keyvals[key]
	if limit != -1 && !currentlyExists && limit < len(mm.keyvals)+1 {
		return errTooManyKeys
	}

	mm.keyvals[key] = value

	return nil
}

// Delete removes the given key.
func (mm *MetadataManager) Delete(key string) {
	mm.Lock()
	defer mm.Unlock()

	delete(mm.keyvals, key)
}

// MetadataSubsManager manages metadata key subscriptions.
type MetadataSubsManager struct {
	sync.RWMutex
	// watchedKeys holds our list of watched (sub'd) keys.
	watchedKeys map[string]bool
}

// NewMetadataSubsManager returns a new MetadataSubsManager.
func NewMetadataSubsManager() *MetadataSubsManager {
	var msm MetadataSubsManager
	msm.watchedKeys = make(map[string]bool)
	return &msm
}

// Sub subscribes to the given keys.
func (msm *MetadataSubsManager) Sub(key ...string) {
	msm.Lock()
	defer msm.Unlock()

	for _, k := range key {
		msm.watchedKeys[k] = true
	}
}

// Unsub ubsubscribes from the given keys.
func (msm *MetadataSubsManager) Unsub(key ...string) {
	msm.Lock()
	defer msm.Unlock()

	for _, k := range key {
		delete(msm.watchedKeys, k)
	}
}

// List returns a list of the currently-subbed keys.
func (msm *MetadataSubsManager) List() []string {
	var keys []string

	msm.RLock()
	defer msm.RUnlock()

	for k := range msm.watchedKeys {
		keys = append(keys, k)
	}

	return keys
}

var (
	metadataValidChars = map[rune]bool{
		'a': true, 'b': true, 'c': true, 'd': true, 'e': true, 'f': true, 'g': true,
		'h': true, 'i': true, 'j': true, 'k': true, 'l': true, 'm': true, 'o': true,
		'p': true, 'q': true, 'r': true, 's': true, 't': true, 'u': true, 'v': true,
		'w': true, 'x': true, 'y': true, 'z': true, '0': true, '1': true, '2': true,
		'3': true, '4': true, '5': true, '6': true, '7': true, '8': true, '9': true,
		'_': true, '-': true, '.': true, ':': true,
	}
)

// metadataKeyValid returns true if the given key is valid.
func metadataKeyValid(key string) bool {
	// key length
	if len(key) < 1 {
		return false
	}
	// invalid first character for a key
	if key[0] == ':' {
		return false
	}
	// name characters
	for _, cha := range []rune(key) {
		if metadataValidChars[rune(cha)] == false {
			return false
		}
	}
	return true
}

var (
	metadataSubcommands = map[string]func(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool{
		"clear": metadataClearHandler,
		"get":   metadataGetHandler,
		"list":  metadataListHandler,
		"set":   metadataSetHandler,
		"sub":   metadataSubHandler,
		"subs":  metadataSubsHandler,
		"sync":  metadataSyncHandler,
		"unsub": metadataUnsubHandler,
	}
)
