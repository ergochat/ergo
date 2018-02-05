// Copyright (c) 2017 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"sync"
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
		entry := cm.chans[name]
		if entry != nil {
			return entry.channel
		}
	}
	return nil
}

// Join causes `client` to join the channel named `name`, creating it if necessary.
func (cm *ChannelManager) Join(client *Client, name string, key string, rb *ResponseBuffer) error {
	server := client.server
	casefoldedName, err := CasefoldChannel(name)
	if err != nil || len(casefoldedName) > server.Limits().ChannelLen {
		return errNoSuchChannel
	}

	cm.Lock()
	entry := cm.chans[casefoldedName]
	if entry == nil {
		// XXX give up the lock to check for a registration, then check again
		// to see if we need to create the channel. we could solve this by doing LoadChannel
		// outside the lock initially on every join, so this is best thought of as an
		// optimization to avoid that.
		cm.Unlock()
		info := client.server.channelRegistry.LoadChannel(casefoldedName)
		cm.Lock()
		entry = cm.chans[casefoldedName]
		if entry == nil {
			entry = &channelManagerEntry{
				channel:      NewChannel(server, name, true, info),
				pendingJoins: 0,
			}
			cm.chans[casefoldedName] = entry
		}
	}
	entry.pendingJoins += 1
	cm.Unlock()

	entry.channel.Join(client, key, rb)

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
	// TODO(slingamn) right now, registered channels cannot be cleaned up.
	// this is because once ChannelManager becomes the source of truth about a channel,
	// we can't move the source of truth back to the database unless we do an ACID
	// store while holding the ChannelManager's Lock(). This is pending more decisions
	// about where the database transaction lock fits into the overall lock model.
	if !entry.channel.IsRegistered() && entry.channel.IsEmpty() && entry.pendingJoins == 0 {
		// reread the name, handling the case where the channel was renamed
		casefoldedName := entry.channel.NameCasefolded()
		delete(cm.chans, casefoldedName)
		// invalidate the entry (otherwise, a subsequent cleanup attempt could delete
		// a valid, distinct entry under casefoldedName):
		entry.channel = nil
	}
}

// Part parts `client` from the channel named `name`, deleting it if it's empty.
func (cm *ChannelManager) Part(client *Client, name string, message string, rb *ResponseBuffer) error {
	casefoldedName, err := CasefoldChannel(name)
	if err != nil {
		return errNoSuchChannel
	}

	cm.RLock()
	entry := cm.chans[casefoldedName]
	cm.RUnlock()

	if entry == nil {
		return errNoSuchChannel
	}
	entry.channel.Part(client, message, rb)
	cm.maybeCleanup(entry, false)
	return nil
}

// Rename renames a channel (but does not notify the members)
func (cm *ChannelManager) Rename(name string, newname string) error {
	cfname, err := CasefoldChannel(name)
	if err != nil {
		return errNoSuchChannel
	}

	cfnewname, err := CasefoldChannel(newname)
	if err != nil {
		return errInvalidChannelName
	}

	cm.Lock()
	defer cm.Unlock()

	if cm.chans[cfnewname] != nil {
		return errChannelNameInUse
	}
	entry := cm.chans[cfname]
	if entry == nil {
		return errNoSuchChannel
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
