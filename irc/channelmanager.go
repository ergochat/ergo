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
	sync.RWMutex       // tier 2
	chans              map[string]*channelManagerEntry
	registeredChannels map[string]bool
	server             *Server
}

// NewChannelManager returns a new ChannelManager.
func (cm *ChannelManager) Initialize(server *Server) {
	cm.chans = make(map[string]*channelManagerEntry)
	cm.server = server

	if server.Config().Channels.Registration.Enabled {
		cm.loadRegisteredChannels()
	}
}

func (cm *ChannelManager) loadRegisteredChannels() {
	registeredChannels := cm.server.channelRegistry.AllChannels()
	cm.Lock()
	defer cm.Unlock()
	cm.registeredChannels = registeredChannels
}

// Get returns an existing channel with name equivalent to `name`, or nil
func (cm *ChannelManager) Get(name string) (channel *Channel) {
	name, err := CasefoldChannel(name)
	if err == nil {
		cm.RLock()
		defer cm.RUnlock()
		entry := cm.chans[name]
		// if the channel is still loading, pretend we don't have it
		if entry != nil && entry.channel.IsLoaded() {
			return entry.channel
		}
	}
	return nil
}

// Join causes `client` to join the channel named `name`, creating it if necessary.
func (cm *ChannelManager) Join(client *Client, name string, key string, isSajoin bool, rb *ResponseBuffer) error {
	server := client.server
	casefoldedName, err := CasefoldChannel(name)
	if err != nil || len(casefoldedName) > server.Config().Limits.ChannelLen {
		return errNoSuchChannel
	}

	channel := func() *Channel {
		cm.Lock()
		defer cm.Unlock()

		entry := cm.chans[casefoldedName]
		if entry == nil {
			registered := cm.registeredChannels[casefoldedName]
			// enforce OpOnlyCreation
			if !registered && server.Config().Channels.OpOnlyCreation && !client.HasRoleCapabs("chanreg") {
				return nil
			}
			entry = &channelManagerEntry{
				channel:      NewChannel(server, name, registered),
				pendingJoins: 0,
			}
			cm.chans[casefoldedName] = entry
		}
		entry.pendingJoins += 1
		return entry.channel
	}()

	if channel == nil {
		return errNoSuchChannel
	}

	channel.EnsureLoaded()
	channel.Join(client, key, isSajoin, rb)

	cm.maybeCleanup(channel, true)

	return nil
}

func (cm *ChannelManager) maybeCleanup(channel *Channel, afterJoin bool) {
	cm.Lock()
	defer cm.Unlock()

	nameCasefolded := channel.NameCasefolded()
	entry := cm.chans[nameCasefolded]
	if entry == nil || entry.channel != channel {
		return
	}

	if afterJoin {
		entry.pendingJoins -= 1
	}
	if entry.pendingJoins == 0 && entry.channel.IsClean() {
		delete(cm.chans, nameCasefolded)
	}
}

// Part parts `client` from the channel named `name`, deleting it if it's empty.
func (cm *ChannelManager) Part(client *Client, name string, message string, rb *ResponseBuffer) error {
	var channel *Channel

	casefoldedName, err := CasefoldChannel(name)
	if err != nil {
		return errNoSuchChannel
	}

	cm.RLock()
	entry := cm.chans[casefoldedName]
	if entry != nil {
		channel = entry.channel
	}
	cm.RUnlock()

	if channel == nil {
		return errNoSuchChannel
	}
	channel.Part(client, message, rb)
	return nil
}

func (cm *ChannelManager) Cleanup(channel *Channel) {
	cm.maybeCleanup(channel, false)
}

func (cm *ChannelManager) SetRegistered(channelName string, account string) (err error) {
	var channel *Channel
	cfname, err := CasefoldChannel(channelName)
	if err != nil {
		return err
	}

	var entry *channelManagerEntry

	defer func() {
		if err == nil && channel != nil {
			// registration was successful: make the database reflect it
			err = channel.Store(IncludeAllChannelAttrs)
		}
	}()

	cm.Lock()
	defer cm.Unlock()
	entry = cm.chans[cfname]
	if entry == nil {
		return errNoSuchChannel
	}
	channel = entry.channel
	err = channel.SetRegistered(account)
	if err != nil {
		return err
	}
	cm.registeredChannels[cfname] = true
	return nil
}

func (cm *ChannelManager) SetUnregistered(channelName string, account string) (err error) {
	cfname, err := CasefoldChannel(channelName)
	if err != nil {
		return err
	}

	var info RegisteredChannel

	defer func() {
		if err == nil {
			err = cm.server.channelRegistry.Delete(info)
		}
	}()

	cm.Lock()
	defer cm.Unlock()
	entry := cm.chans[cfname]
	if entry == nil {
		return errNoSuchChannel
	}
	info = entry.channel.ExportRegistration(0)
	if info.Founder != account {
		return errChannelNotOwnedByAccount
	}
	entry.channel.SetUnregistered(account)
	delete(cm.registeredChannels, cfname)
	return nil
}

// Rename renames a channel (but does not notify the members)
func (cm *ChannelManager) Rename(name string, newname string) (err error) {
	cfname, err := CasefoldChannel(name)
	if err != nil {
		return errNoSuchChannel
	}

	cfnewname, err := CasefoldChannel(newname)
	if err != nil {
		return errInvalidChannelName
	}

	var channel *Channel
	var info RegisteredChannel
	defer func() {
		if channel != nil && info.Founder != "" {
			channel.Store(IncludeAllChannelAttrs)
			// we just flushed the channel under its new name, therefore this delete
			// cannot be overwritten by a write to the old name:
			cm.server.channelRegistry.Delete(info)
		}
	}()

	cm.Lock()
	defer cm.Unlock()

	if cm.chans[cfnewname] != nil || cm.registeredChannels[cfnewname] {
		return errChannelNameInUse
	}
	entry := cm.chans[cfname]
	if entry == nil {
		return errNoSuchChannel
	}
	channel = entry.channel
	info = channel.ExportRegistration(IncludeInitial)
	delete(cm.chans, cfname)
	cm.chans[cfnewname] = entry
	if cm.registeredChannels[cfname] {
		delete(cm.registeredChannels, cfname)
		cm.registeredChannels[cfnewname] = true
	}
	entry.channel.Rename(newname, cfnewname)
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
	result = make([]*Channel, 0, len(cm.chans))
	for _, entry := range cm.chans {
		if entry.channel.IsLoaded() {
			result = append(result, entry.channel)
		}
	}
	return
}
