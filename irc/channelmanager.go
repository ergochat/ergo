// Copyright (c) 2017 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"sort"
	"sync"
	"time"

	"github.com/ergochat/ergo/irc/datastore"
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
	chans          map[string]*channelManagerEntry
	chansSkeletons utils.HashSet[string]
	purgedChannels map[string]ChannelPurgeRecord // casefolded name to purge record
	server         *Server
}

// NewChannelManager returns a new ChannelManager.
func (cm *ChannelManager) Initialize(server *Server, config *Config) (err error) {
	cm.chans = make(map[string]*channelManagerEntry)
	cm.chansSkeletons = make(utils.HashSet[string])
	cm.server = server
	return cm.loadRegisteredChannels(config)
}

func (cm *ChannelManager) loadRegisteredChannels(config *Config) (err error) {
	allChannels, err := FetchAndDeserializeAll[RegisteredChannel](datastore.TableChannels, cm.server.dstore, cm.server.logger)
	if err != nil {
		return
	}
	allPurgeRecords, err := FetchAndDeserializeAll[ChannelPurgeRecord](datastore.TableChannelPurges, cm.server.dstore, cm.server.logger)
	if err != nil {
		return
	}

	cm.Lock()
	defer cm.Unlock()

	cm.purgedChannels = make(map[string]ChannelPurgeRecord, len(allPurgeRecords))
	for _, purge := range allPurgeRecords {
		cm.purgedChannels[purge.NameCasefolded] = purge
	}

	for _, regInfo := range allChannels {
		cfname, err := CasefoldChannel(regInfo.Name)
		if err != nil {
			cm.server.logger.Error("channels", "couldn't casefold registered channel, skipping", regInfo.Name, err.Error())
			continue
		} else {
			cm.server.logger.Debug("channels", "initializing registered channel", regInfo.Name)
		}
		skeleton, err := Skeleton(regInfo.Name)
		if err == nil {
			cm.chansSkeletons.Add(skeleton)
		}

		if _, ok := cm.purgedChannels[cfname]; !ok {
			ch := NewChannel(cm.server, regInfo.Name, cfname, true, regInfo)
			cm.chans[cfname] = &channelManagerEntry{
				channel:      ch,
				pendingJoins: 0,
				skeleton:     skeleton,
			}
		}
	}

	return nil
}

// Get returns an existing channel with name equivalent to `name`, or nil
func (cm *ChannelManager) Get(name string) (channel *Channel) {
	name, err := CasefoldChannel(name)
	if err != nil {
		return nil
	}
	cm.RLock()
	defer cm.RUnlock()
	entry := cm.chans[name]
	if entry != nil {
		return entry.channel
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

		// check purges first; a registered purged channel will still be present in `chans`
		if _, ok := cm.purgedChannels[casefoldedName]; ok {
			return nil, errChannelPurged, false
		}
		entry := cm.chans[casefoldedName]
		if entry == nil {
			if server.Config().Channels.OpOnlyCreation &&
				!(isSajoin || client.HasRoleCapabs("chanreg")) {
				return nil, errInsufficientPrivs, false
			}
			// enforce confusables
			if cm.chansSkeletons.Has(skeleton) {
				return nil, errConfusableIdentifier, false
			}
			entry = &channelManagerEntry{
				channel:      NewChannel(server, name, casefoldedName, false, RegisteredChannel{}),
				pendingJoins: 0,
			}
			cm.chansSkeletons.Add(skeleton)
			entry.skeleton = skeleton
			cm.chans[casefoldedName] = entry
			newChannel = true
		}
		entry.pendingJoins += 1
		return entry.channel, nil, newChannel
	}()

	if err != nil {
		return err, ""
	}

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
	return nil
}

func (cm *ChannelManager) SetUnregistered(channelName string, account string) (err error) {
	cfname, err := CasefoldChannel(channelName)
	if err != nil {
		return err
	}

	var uuid utils.UUID

	defer func() {
		if err == nil {
			if delErr := cm.server.dstore.Delete(datastore.TableChannels, uuid); delErr != nil {
				cm.server.logger.Error("datastore", "couldn't delete channel registration", cfname, delErr.Error())
			}
		}
	}()

	cm.Lock()
	defer cm.Unlock()
	entry := cm.chans[cfname]
	if entry != nil {
		if entry.channel.Founder() != account {
			return errChannelNotOwnedByAccount
		}
		uuid = entry.channel.UUID()
		entry.channel.SetUnregistered(account) // changes the UUID
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
			channel.MarkDirty(IncludeAllAttrs)
		}
		// always-on clients need to update their saved channel memberships
		for _, member := range channel.Members() {
			member.markDirty(IncludeChannels)
		}
	}()

	cm.Lock()
	defer cm.Unlock()

	entry := cm.chans[oldCfname]
	if entry == nil {
		return errNoSuchChannel
	}
	channel = entry.channel
	info = channel.ExportRegistration()
	registered := info.Founder != ""

	oldSkeleton, err := Skeleton(info.Name)
	if err != nil {
		return errNoSuchChannel // ugh
	}

	if newCfname != oldCfname {
		if cm.chans[newCfname] != nil {
			return errChannelNameInUse
		}
	}

	if oldSkeleton != newSkeleton {
		if cm.chansSkeletons.Has(newSkeleton) {
			return errConfusableIdentifier
		}
	}

	delete(cm.chans, oldCfname)
	if !registered {
		entry.skeleton = newSkeleton
	}
	cm.chans[newCfname] = entry
	delete(cm.chansSkeletons, oldSkeleton)
	cm.chansSkeletons.Add(newSkeleton)
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
		result = append(result, entry.channel)
	}
	return
}

// ListableChannels returns a slice of all non-purged channels.
func (cm *ChannelManager) ListableChannels() (result []*Channel) {
	cm.RLock()
	defer cm.RUnlock()
	result = make([]*Channel, 0, len(cm.chans))
	for cfname, entry := range cm.chans {
		if _, ok := cm.purgedChannels[cfname]; !ok {
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

	record.NameCasefolded = chname
	record.UUID = utils.GenerateUUIDv4()

	channel, err := func() (channel *Channel, err error) {
		cm.Lock()
		defer cm.Unlock()

		if _, ok := cm.purgedChannels[chname]; ok {
			return nil, errChannelPurgedAlready
		}

		entry := cm.chans[chname]
		// atomically prevent anyone from rejoining
		cm.purgedChannels[chname] = record
		if entry != nil {
			channel = entry.channel
		}
		return
	}()

	if err != nil {
		return err
	}

	if channel != nil {
		// actually kick everyone off the channel
		channel.Purge("")
	}

	var purgeBytes []byte
	if purgeBytes, err = record.Serialize(); err != nil {
		cm.server.logger.Error("internal", "couldn't serialize purge record", channel.Name(), err.Error())
	}
	// TODO we need a better story about error handling for later
	if err = cm.server.dstore.Set(datastore.TableChannelPurges, record.UUID, purgeBytes, time.Time{}); err != nil {
		cm.server.logger.Error("datastore", "couldn't store purge record", chname, err.Error())
	}

	return
}

// IsPurged queries whether a channel is purged.
func (cm *ChannelManager) IsPurged(chname string) (result bool) {
	chname, err := CasefoldChannel(chname)
	if err != nil {
		return false
	}

	cm.RLock()
	_, result = cm.purgedChannels[chname]
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
	record, found := cm.purgedChannels[chname]
	delete(cm.purgedChannels, chname)
	cm.Unlock()

	if !found {
		return errNoSuchChannel
	}
	if err := cm.server.dstore.Delete(datastore.TableChannelPurges, record.UUID); err != nil {
		cm.server.logger.Error("datastore", "couldn't delete purge record", chname, err.Error())
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
	if entry != nil {
		return entry.channel.Name()
	}
	return cfname
}

func (cm *ChannelManager) LoadPurgeRecord(cfchname string) (record ChannelPurgeRecord, err error) {
	cm.RLock()
	defer cm.RUnlock()

	if record, ok := cm.purgedChannels[cfchname]; ok {
		return record, nil
	} else {
		return record, errNoSuchChannel
	}
}

func (cm *ChannelManager) ChannelsForAccount(account string) (channels []string) {
	cm.RLock()
	defer cm.RUnlock()

	for cfname, entry := range cm.chans {
		if entry.channel.Founder() == account {
			channels = append(channels, cfname)
		}
	}

	return
}

// AllChannels returns the uncasefolded names of all registered channels.
func (cm *ChannelManager) AllRegisteredChannels() (result []string) {
	cm.RLock()
	defer cm.RUnlock()

	for cfname, entry := range cm.chans {
		if entry.channel.Founder() != "" {
			result = append(result, cfname)
		}
	}

	return
}
