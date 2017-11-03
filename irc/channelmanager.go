// Copyright (c) 2017 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"errors"
	"sync"
)

var (
	InvalidChannelName = errors.New("Invalid channel name")
	NoSuchChannel      = errors.New("No such channel")
	ChannelNameInUse   = errors.New("Channel name in use")
)

type channelManagerEntry struct {
	channel *Channel
	// this is a refcount for joins, so we can avoid a race where we incorrectly
	// think the channel is empty (without holding a lock across the entire Channel.Join()
	// call)
	pendingJoins int
}

// ChannelManager keeps track of all the channels on the server,
// providing synchronization for creation of new channels on first join,
// cleanup of empty channels on last part, and renames.
type ChannelManager struct {
	sync.RWMutex // tier 2
	chans        map[string]*channelManagerEntry
}

// NewChannelManager returns a new ChannelManager.
func NewChannelManager() *ChannelManager {
	return &ChannelManager{
		chans: make(map[string]*channelManagerEntry),
	}
}

// Get returns an existing channel with name equivalent to `name`, or nil
func (cm *ChannelManager) Get(name string) *Channel {
	name, err := CasefoldChannel(name)
	if err == nil {
		cm.RLock()
		defer cm.RUnlock()
		return cm.chans[name].channel
	}
	return nil
}

// Join causes `client` to join the channel named `name`, creating it if necessary.
func (cm *ChannelManager) Join(client *Client, name string, key string) error {
	server := client.server
	casefoldedName, err := CasefoldChannel(name)
	if err != nil || len(casefoldedName) > server.Limits().ChannelLen {
		return NoSuchChannel
	}

	cm.Lock()
	entry := cm.chans[casefoldedName]
	if entry == nil {
		entry = &channelManagerEntry{
			channel:      NewChannel(server, name, true),
			pendingJoins: 0,
		}
		cm.chans[casefoldedName] = entry
	}
	entry.pendingJoins += 1
	cm.Unlock()

	entry.channel.Join(client, key)

	cm.maybeCleanup(entry, true)

	return nil
}

func (cm *ChannelManager) maybeCleanup(entry *channelManagerEntry, afterJoin bool) {
	cm.Lock()
	defer cm.Unlock()

	if entry.channel == nil {
		return
	}
	if afterJoin {
		entry.pendingJoins -= 1
	}
	if entry.channel.IsEmpty() && entry.pendingJoins == 0 {
		// reread the name, handling the case where the channel was renamed
		casefoldedName := entry.channel.NameCasefolded()
		delete(cm.chans, casefoldedName)
		// invalidate the entry (otherwise, a subsequent cleanup attempt could delete
		// a valid, distinct entry under casefoldedName):
		entry.channel = nil
	}
}

// Part parts `client` from the channel named `name`, deleting it if it's empty.
func (cm *ChannelManager) Part(client *Client, name string, message string) error {
	casefoldedName, err := CasefoldChannel(name)
	if err != nil {
		return NoSuchChannel
	}

	cm.RLock()
	entry := cm.chans[casefoldedName]
	cm.RUnlock()

	if entry == nil {
		return NoSuchChannel
	}
	entry.channel.Part(client, message)
	cm.maybeCleanup(entry, false)
	return nil
}

// Rename renames a channel (but does not notify the members)
func (cm *ChannelManager) Rename(name string, newname string) error {
	cfname, err := CasefoldChannel(name)
	if err != nil {
		return NoSuchChannel
	}

	cfnewname, err := CasefoldChannel(newname)
	if err != nil {
		return InvalidChannelName
	}

	cm.Lock()
	defer cm.Unlock()

	if cm.chans[cfnewname] != nil {
		return ChannelNameInUse
	}
	entry := cm.chans[cfname]
	if entry == nil {
		return NoSuchChannel
	}
	delete(cm.chans, cfname)
	cm.chans[cfnewname] = entry
	entry.channel.setName(newname)
	entry.channel.setNameCasefolded(cfnewname)
	return nil

}

// Len returns the number of channels
func (cm *ChannelManager) Len() int {
	cm.RLock()
	defer cm.RUnlock()
	return len(cm.chans)
}

// Channels returns a slice containing all current channels
func (cm *ChannelManager) Channels() (result []*Channel) {
	cm.RLock()
	defer cm.RUnlock()
	for _, entry := range cm.chans {
		result = append(result, entry.channel)
	}
	return
}
