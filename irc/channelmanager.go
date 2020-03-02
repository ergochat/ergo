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
	skeleton     string
}

// ChannelManager keeps track of all the channels on the server,
// providing synchronization for creation of new channels on first join,
// cleanup of empty channels on last part, and renames.
type ChannelManager struct {
	sync.RWMutex // tier 2
	// chans is the main data structure, mapping casefolded name -> *Channel
	chans               map[string]*channelManagerEntry
	chansSkeletons      StringSet // skeletons of *unregistered* chans
	registeredChannels  StringSet // casefolds of registered chans
	registeredSkeletons StringSet // skeletons of registered chans
	purgedChannels      StringSet // casefolds of purged chans
	server              *Server
}

// NewChannelManager returns a new ChannelManager.
func (cm *ChannelManager) Initialize(server *Server) {
	cm.chans = make(map[string]*channelManagerEntry)
	cm.chansSkeletons = make(StringSet)
	cm.server = server

	cm.loadRegisteredChannels(server.Config())
	// purging should work even if registration is disabled
	cm.purgedChannels = cm.server.channelRegistry.PurgedChannels()
}

func (cm *ChannelManager) loadRegisteredChannels(config *Config) {
	if !config.Channels.Registration.Enabled {
		return
	}

	rawNames := cm.server.channelRegistry.AllChannels()
	registeredChannels := make(StringSet, len(rawNames))
	registeredSkeletons := make(StringSet, len(rawNames))
	for _, name := range rawNames {
		cfname, err := CasefoldChannel(name)
		if err == nil {
			registeredChannels.Add(cfname)
		}
		skeleton, err := Skeleton(name)
		if err == nil {
			registeredSkeletons.Add(skeleton)
		}
	}
	cm.Lock()
	defer cm.Unlock()
	cm.registeredChannels = registeredChannels
	cm.registeredSkeletons = registeredSkeletons
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
	skeleton, skerr := Skeleton(name)
	if err != nil || skerr != nil || len(casefoldedName) > server.Config().Limits.ChannelLen {
		return errNoSuchChannel
	}

	channel, err := func() (*Channel, error) {
		cm.Lock()
		defer cm.Unlock()

		if cm.purgedChannels.Has(casefoldedName) {
			return nil, errChannelPurged
		}
		entry := cm.chans[casefoldedName]
		if entry == nil {
			registered := cm.registeredChannels.Has(casefoldedName)
			// enforce OpOnlyCreation
			if !registered && server.Config().Channels.OpOnlyCreation && !client.HasRoleCapabs("chanreg") {
				return nil, errInsufficientPrivs
			}
			// enforce confusables
			if cm.chansSkeletons.Has(skeleton) || (!registered && cm.registeredSkeletons.Has(skeleton)) {
				return nil, errConfusableIdentifier
			}
			entry = &channelManagerEntry{
				channel:      NewChannel(server, name, casefoldedName, registered),
				pendingJoins: 0,
			}
			if !registered {
				// for an unregistered channel, we already have the correct unfolded name
				// and therefore the final skeleton. for a registered channel, we don't have
				// the unfolded name yet (it needs to be loaded from the db), but we already
				// have the final skeleton in `registeredSkeletons` so we don't need to track it
				cm.chansSkeletons.Add(skeleton)
				entry.skeleton = skeleton
			}
			cm.chans[casefoldedName] = entry
		}
		entry.pendingJoins += 1
		return entry.channel, nil
	}()

	if err != nil {
		return err
	}

	channel.EnsureLoaded()
	channel.Join(client, key, isSajoin, rb)

	cm.maybeCleanup(channel, true)

	return nil
}

func (cm *ChannelManager) maybeCleanup(channel *Channel, afterJoin bool) {
	cm.Lock()
	defer cm.Unlock()

	cfname := channel.NameCasefolded()

	entry := cm.chans[cfname]
	if entry == nil || entry.channel != channel {
		return
	}

	if afterJoin {
		entry.pendingJoins -= 1
	}
	if entry.pendingJoins == 0 && entry.channel.IsClean() {
		delete(cm.chans, cfname)
		if entry.skeleton != "" {
			delete(cm.chansSkeletons, entry.skeleton)
		}
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
			err = channel.Store(IncludeAllAttrs)
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
	cm.registeredChannels.Add(cfname)
	if skel, err := Skeleton(channel.Name()); err == nil {
		cm.registeredSkeletons.Add(skel)
	}
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
	if skel, err := Skeleton(entry.channel.Name()); err == nil {
		delete(cm.registeredSkeletons, skel)
	}
	return nil
}

// Rename renames a channel (but does not notify the members)
func (cm *ChannelManager) Rename(name string, newName string) (err error) {
	cfname, err := CasefoldChannel(name)
	if err != nil {
		return errNoSuchChannel
	}

	newCfname, err := CasefoldChannel(newName)
	if err != nil {
		return errInvalidChannelName
	}
	newSkeleton, err := Skeleton(newName)
	if err != nil {
		return errInvalidChannelName
	}

	var channel *Channel
	var info RegisteredChannel
	defer func() {
		if channel != nil && info.Founder != "" {
			channel.Store(IncludeAllAttrs)
			// we just flushed the channel under its new name, therefore this delete
			// cannot be overwritten by a write to the old name:
			cm.server.channelRegistry.Delete(info)
		}
	}()

	cm.Lock()
	defer cm.Unlock()

	if cm.chans[newCfname] != nil || cm.registeredChannels.Has(newCfname) {
		return errChannelNameInUse
	}
	if cm.chansSkeletons.Has(newSkeleton) || cm.registeredSkeletons.Has(newSkeleton) {
		return errChannelNameInUse
	}
	entry := cm.chans[cfname]
	if entry == nil || !entry.channel.IsLoaded() {
		return errNoSuchChannel
	}
	channel = entry.channel
	info = channel.ExportRegistration(IncludeInitial)
	registered := info.Founder != ""
	delete(cm.chans, cfname)
	cm.chans[newCfname] = entry
	if registered {
		delete(cm.registeredChannels, cfname)
		if oldSkeleton, err := Skeleton(info.Name); err == nil {
			delete(cm.registeredSkeletons, oldSkeleton)
		}
		cm.registeredChannels.Add(newCfname)
		cm.registeredSkeletons.Add(newSkeleton)
	} else {
		delete(cm.chansSkeletons, entry.skeleton)
		cm.chansSkeletons.Add(newSkeleton)
		entry.skeleton = newSkeleton
		cm.chans[cfname] = entry
	}
	entry.channel.Rename(newName, newCfname)
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

// Purge marks a channel as purged.
func (cm *ChannelManager) Purge(chname string, record ChannelPurgeRecord) (err error) {
	chname, err = CasefoldChannel(chname)
	if err != nil {
		return errInvalidChannelName
	}

	cm.Lock()
	cm.purgedChannels.Add(chname)
	cm.Unlock()

	cm.server.channelRegistry.PurgeChannel(chname, record)
	return nil
}

// IsPurged queries whether a channel is purged.
func (cm *ChannelManager) IsPurged(chname string) (result bool) {
	chname, err := CasefoldChannel(chname)
	if err != nil {
		return false
	}

	cm.RLock()
	result = cm.purgedChannels.Has(chname)
	cm.RUnlock()
	return
}

// Unpurge deletes a channel's purged status.
func (cm *ChannelManager) Unpurge(chname string) (err error) {
	chname, err = CasefoldChannel(chname)
	if err != nil {
		return errNoSuchChannel
	}

	cm.Lock()
	found := cm.purgedChannels.Has(chname)
	delete(cm.purgedChannels, chname)
	cm.Unlock()

	cm.server.channelRegistry.UnpurgeChannel(chname)
	if !found {
		return errNoSuchChannel
	}
	return nil
}
