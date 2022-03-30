// Copyright (c) 2017 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"sort"
	"sync"

	"github.com/ergochat/ergo/irc/utils"
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
	chansSkeletons      utils.HashSet[string] // skeletons of *unregistered* chans
	registeredChannels  utils.HashSet[string] // casefolds of registered chans
	registeredSkeletons utils.HashSet[string] // skeletons of registered chans
	purgedChannels      utils.HashSet[string] // casefolds of purged chans
	server              *Server
}

// NewChannelManager returns a new ChannelManager.
func (cm *ChannelManager) Initialize(server *Server) {
	cm.chans = make(map[string]*channelManagerEntry)
	cm.chansSkeletons = make(utils.HashSet[string])
	cm.server = server

	// purging should work even if registration is disabled
	cm.purgedChannels = cm.server.channelRegistry.PurgedChannels()
	cm.loadRegisteredChannels(server.Config())
}

func (cm *ChannelManager) loadRegisteredChannels(config *Config) {
	if !config.Channels.Registration.Enabled {
		return
	}

	var newChannels []*Channel
	var collisions []string
	defer func() {
		for _, ch := range newChannels {
			ch.EnsureLoaded()
			cm.server.logger.Debug("channels", "initialized registered channel", ch.Name())
		}
		for _, collision := range collisions {
			cm.server.logger.Warning("channels", "registered channel collides with existing channel", collision)
		}
	}()

	rawNames := cm.server.channelRegistry.AllChannels()

	cm.Lock()
	defer cm.Unlock()

	cm.registeredChannels = make(utils.HashSet[string], len(rawNames))
	cm.registeredSkeletons = make(utils.HashSet[string], len(rawNames))
	for _, name := range rawNames {
		cfname, err := CasefoldChannel(name)
		if err == nil {
			cm.registeredChannels.Add(cfname)
		}
		skeleton, err := Skeleton(name)
		if err == nil {
			cm.registeredSkeletons.Add(skeleton)
		}

		if !cm.purgedChannels.Has(cfname) {
			if _, ok := cm.chans[cfname]; !ok {
				ch := NewChannel(cm.server, name, cfname, true)
				cm.chans[cfname] = &channelManagerEntry{
					channel:      ch,
					pendingJoins: 0,
				}
				newChannels = append(newChannels, ch)
			} else {
				collisions = append(collisions, name)
			}
		}
	}
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
func (cm *ChannelManager) Join(client *Client, name string, key string, isSajoin bool, rb *ResponseBuffer) (err error, forward string) {
	server := client.server
	casefoldedName, err := CasefoldChannel(name)
	skeleton, skerr := Skeleton(name)
	if err != nil || skerr != nil || len(casefoldedName) > server.Config().Limits.ChannelLen {
		return errNoSuchChannel, ""
	}

	channel, err, newChannel := func() (*Channel, error, bool) {
		var newChannel bool
		cm.Lock()
		defer cm.Unlock()

		if cm.purgedChannels.Has(casefoldedName) {
			return nil, errChannelPurged, false
		}
		entry := cm.chans[casefoldedName]
		if entry == nil {
			registered := cm.registeredChannels.Has(casefoldedName)
			// enforce OpOnlyCreation
			if !registered && server.Config().Channels.OpOnlyCreation &&
				!(isSajoin || client.HasRoleCapabs("chanreg")) {
				return nil, errInsufficientPrivs, false
			}
			// enforce confusables
			if !registered && (cm.chansSkeletons.Has(skeleton) || cm.registeredSkeletons.Has(skeleton)) {
				return nil, errConfusableIdentifier, false
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
			newChannel = true
		}
		entry.pendingJoins += 1
		return entry.channel, nil, newChannel
	}()

	if err != nil {
		return err, ""
	}

	channel.EnsureLoaded()
	err, forward = channel.Join(client, key, isSajoin || newChannel, rb)

	cm.maybeCleanup(channel, true)

	return
}

func (cm *ChannelManager) maybeCleanup(channel *Channel, afterJoin bool) {
	cm.Lock()
	defer cm.Unlock()

	cfname := channel.NameCasefolded()

	entry := cm.chans[cfname]
	if entry == nil || entry.channel != channel {
		return
	}

	cm.maybeCleanupInternal(cfname, entry, afterJoin)
}

func (cm *ChannelManager) maybeCleanupInternal(cfname string, entry *channelManagerEntry, afterJoin bool) {
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
	if cm.server.Defcon() <= 4 {
		return errFeatureDisabled
	}

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
	// transfer the skeleton from chansSkeletons to registeredSkeletons
	skeleton := entry.skeleton
	delete(cm.chansSkeletons, skeleton)
	entry.skeleton = ""
	cm.chans[cfname] = entry
	cm.registeredChannels.Add(cfname)
	cm.registeredSkeletons.Add(skeleton)
	return nil
}

func (cm *ChannelManager) SetUnregistered(channelName string, account string) (err error) {
	cfname, err := CasefoldChannel(channelName)
	if err != nil {
		return err
	}

	info, err := cm.server.channelRegistry.LoadChannel(cfname)
	if err != nil {
		return err
	}
	if info.Founder != account {
		return errChannelNotOwnedByAccount
	}

	defer func() {
		if err == nil {
			err = cm.server.channelRegistry.Delete(info)
		}
	}()

	cm.Lock()
	defer cm.Unlock()
	entry := cm.chans[cfname]
	if entry != nil {
		entry.channel.SetUnregistered(account)
		delete(cm.registeredChannels, cfname)
		// transfer the skeleton from registeredSkeletons to chansSkeletons
		if skel, err := Skeleton(entry.channel.Name()); err == nil {
			delete(cm.registeredSkeletons, skel)
			cm.chansSkeletons.Add(skel)
			entry.skeleton = skel
			cm.chans[cfname] = entry
		}
		// #1619: if the channel has 0 members and was only being retained
		// because it was registered, clean it up:
		cm.maybeCleanupInternal(cfname, entry, false)
	}
	return nil
}

// Rename renames a channel (but does not notify the members)
func (cm *ChannelManager) Rename(name string, newName string) (err error) {
	oldCfname, err := CasefoldChannel(name)
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
			if oldCfname != newCfname {
				// we just flushed the channel under its new name, therefore this delete
				// cannot be overwritten by a write to the old name:
				cm.server.channelRegistry.Delete(info)
			}
		}
	}()

	cm.Lock()
	defer cm.Unlock()

	entry := cm.chans[oldCfname]
	if entry == nil || !entry.channel.IsLoaded() {
		return errNoSuchChannel
	}
	channel = entry.channel
	info = channel.ExportRegistration(IncludeInitial)
	registered := info.Founder != ""

	oldSkeleton, err := Skeleton(info.Name)
	if err != nil {
		return errNoSuchChannel // ugh
	}

	if newCfname != oldCfname {
		if cm.chans[newCfname] != nil || cm.registeredChannels.Has(newCfname) {
			return errChannelNameInUse
		}
	}

	if oldSkeleton != newSkeleton {
		if cm.chansSkeletons.Has(newSkeleton) || cm.registeredSkeletons.Has(newSkeleton) {
			return errConfusableIdentifier
		}
	}

	delete(cm.chans, oldCfname)
	if !registered {
		entry.skeleton = newSkeleton
	}
	cm.chans[newCfname] = entry
	if registered {
		delete(cm.registeredChannels, oldCfname)
		cm.registeredChannels.Add(newCfname)
		delete(cm.registeredSkeletons, oldSkeleton)
		cm.registeredSkeletons.Add(newSkeleton)
	} else {
		delete(cm.chansSkeletons, oldSkeleton)
		cm.chansSkeletons.Add(newSkeleton)
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
	skel, err := Skeleton(chname)
	if err != nil {
		return errInvalidChannelName
	}

	cm.Lock()
	cm.purgedChannels.Add(chname)
	entry := cm.chans[chname]
	if entry != nil {
		delete(cm.chans, chname)
		if entry.channel.Founder() != "" {
			delete(cm.registeredSkeletons, skel)
		} else {
			delete(cm.chansSkeletons, skel)
		}
	}
	cm.Unlock()

	cm.server.channelRegistry.PurgeChannel(chname, record)
	if entry != nil {
		entry.channel.Purge("")
	}
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

func (cm *ChannelManager) ListPurged() (result []string) {
	cm.RLock()
	result = make([]string, 0, len(cm.purgedChannels))
	for c := range cm.purgedChannels {
		result = append(result, c)
	}
	cm.RUnlock()
	sort.Strings(result)
	return
}

func (cm *ChannelManager) UnfoldName(cfname string) (result string) {
	cm.RLock()
	entry := cm.chans[cfname]
	cm.RUnlock()
	if entry != nil && entry.channel.IsLoaded() {
		return entry.channel.Name()
	}
	return cfname
}
