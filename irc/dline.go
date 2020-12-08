// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/oragono/oragono/irc/flatip"
	"github.com/oragono/oragono/irc/utils"
	"github.com/tidwall/buntdb"
)

const (
	keyDlineEntry = "bans.dlinev2 %s"
)

// IPBanInfo holds info about an IP/net ban.
type IPBanInfo struct {
	// Reason is the ban reason.
	Reason string `json:"reason"`
	// OperReason is an oper ban reason.
	OperReason string `json:"oper_reason"`
	// OperName is the oper who set the ban.
	OperName string `json:"oper_name"`
	// time of ban creation
	TimeCreated time.Time
	// duration of the ban; 0 means "permanent"
	Duration time.Duration
}

func (info IPBanInfo) timeLeft() time.Duration {
	return time.Until(info.TimeCreated.Add(info.Duration))
}

func (info IPBanInfo) TimeLeft() string {
	if info.Duration == 0 {
		return "indefinite"
	} else {
		return info.timeLeft().Truncate(time.Second).String()
	}
}

// BanMessage returns the ban message.
func (info IPBanInfo) BanMessage(message string) string {
	message = fmt.Sprintf(message, info.Reason)
	if info.Duration != 0 {
		message += fmt.Sprintf(" [%s]", info.TimeLeft())
	}
	return message
}

// DLineManager manages and dlines.
type DLineManager struct {
	sync.RWMutex                // tier 1
	persistenceMutex sync.Mutex // tier 2
	// networks that are dlined:
	networks map[flatip.IPNet]IPBanInfo
	// this keeps track of expiration timers for temporary bans
	expirationTimers map[flatip.IPNet]*time.Timer
	server           *Server
}

// NewDLineManager returns a new DLineManager.
func NewDLineManager(server *Server) *DLineManager {
	var dm DLineManager
	dm.networks = make(map[flatip.IPNet]IPBanInfo)
	dm.expirationTimers = make(map[flatip.IPNet]*time.Timer)
	dm.server = server

	dm.loadFromDatastore()

	return &dm
}

// AllBans returns all bans (for use with APIs, etc).
func (dm *DLineManager) AllBans() map[string]IPBanInfo {
	allb := make(map[string]IPBanInfo)

	dm.RLock()
	defer dm.RUnlock()

	for key, info := range dm.networks {
		allb[key.String()] = info
	}

	return allb
}

// AddNetwork adds a network to the blocked list.
func (dm *DLineManager) AddNetwork(network net.IPNet, duration time.Duration, reason, operReason, operName string) error {
	dm.persistenceMutex.Lock()
	defer dm.persistenceMutex.Unlock()

	// assemble ban info
	info := IPBanInfo{
		Reason:      reason,
		OperReason:  operReason,
		OperName:    operName,
		TimeCreated: time.Now().UTC(),
		Duration:    duration,
	}

	id := dm.addNetworkInternal(network, info)
	return dm.persistDline(id, info)
}

func (dm *DLineManager) addNetworkInternal(network net.IPNet, info IPBanInfo) (id flatip.IPNet) {
	flatnet := flatip.FromNetIPNet(network)
	id = flatnet

	var timeLeft time.Duration
	if info.Duration != 0 {
		timeLeft = info.timeLeft()
		if timeLeft <= 0 {
			return
		}
	}

	dm.Lock()
	defer dm.Unlock()

	dm.networks[flatnet] = info

	dm.cancelTimer(flatnet)

	if info.Duration == 0 {
		return
	}

	// set up new expiration timer
	timeCreated := info.TimeCreated
	processExpiration := func() {
		dm.Lock()
		defer dm.Unlock()

		banInfo, ok := dm.networks[flatnet]
		if ok && banInfo.TimeCreated.Equal(timeCreated) {
			delete(dm.networks, flatnet)
			// TODO(slingamn) here's where we'd remove it from the radix tree
			delete(dm.expirationTimers, flatnet)
		}
	}
	dm.expirationTimers[flatnet] = time.AfterFunc(timeLeft, processExpiration)

	return
}

func (dm *DLineManager) cancelTimer(flatnet flatip.IPNet) {
	oldTimer := dm.expirationTimers[flatnet]
	if oldTimer != nil {
		oldTimer.Stop()
		delete(dm.expirationTimers, flatnet)
	}
}

func (dm *DLineManager) persistDline(id flatip.IPNet, info IPBanInfo) error {
	// save in datastore
	dlineKey := fmt.Sprintf(keyDlineEntry, id.String())
	// assemble json from ban info
	b, err := json.Marshal(info)
	if err != nil {
		dm.server.logger.Error("internal", "couldn't marshal d-line", err.Error())
		return err
	}
	bstr := string(b)
	var setOptions *buntdb.SetOptions
	if info.Duration != 0 {
		setOptions = &buntdb.SetOptions{Expires: true, TTL: info.Duration}
	}

	err = dm.server.store.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(dlineKey, bstr, setOptions)
		return err
	})
	if err != nil {
		dm.server.logger.Error("internal", "couldn't store d-line", err.Error())
	}
	return err
}

func (dm *DLineManager) unpersistDline(id flatip.IPNet) error {
	dlineKey := fmt.Sprintf(keyDlineEntry, id.String())
	return dm.server.store.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(dlineKey)
		return err
	})
}

// RemoveNetwork removes a network from the blocked list.
func (dm *DLineManager) RemoveNetwork(network net.IPNet) error {
	dm.persistenceMutex.Lock()
	defer dm.persistenceMutex.Unlock()

	id := flatip.FromNetIPNet(network)

	present := func() bool {
		dm.Lock()
		defer dm.Unlock()
		_, ok := dm.networks[id]
		delete(dm.networks, id)
		dm.cancelTimer(id)
		return ok
	}()

	if !present {
		return errNoExistingBan
	}

	return dm.unpersistDline(id)
}

// AddIP adds an IP address to the blocked list.
func (dm *DLineManager) AddIP(addr net.IP, duration time.Duration, reason, operReason, operName string) error {
	return dm.AddNetwork(utils.NormalizeIPToNet(addr), duration, reason, operReason, operName)
}

// RemoveIP removes an IP address from the blocked list.
func (dm *DLineManager) RemoveIP(addr net.IP) error {
	return dm.RemoveNetwork(utils.NormalizeIPToNet(addr))
}

// CheckIP returns whether or not an IP address was banned, and how long it is banned for.
func (dm *DLineManager) CheckIP(netAddr net.IP) (isBanned bool, info IPBanInfo) {
	addr := flatip.FromNetIP(netAddr)
	if addr.IsLoopback() {
		return // #671
	}

	dm.RLock()
	defer dm.RUnlock()

	// check networks
	// TODO(slingamn) use a radix tree as the data plane for this
	for flatnet, info := range dm.networks {
		if flatnet.Contains(addr) {
			return true, info
		}
	}
	// no matches!
	return
}

func (dm *DLineManager) loadFromDatastore() {
	dlinePrefix := fmt.Sprintf(keyDlineEntry, "")
	dm.server.store.View(func(tx *buntdb.Tx) error {
		tx.AscendGreaterOrEqual("", dlinePrefix, func(key, value string) bool {
			if !strings.HasPrefix(key, dlinePrefix) {
				return false
			}

			// get address name
			key = strings.TrimPrefix(key, dlinePrefix)

			// load addr/net
			hostNet, err := utils.NormalizedNetFromString(key)
			if err != nil {
				dm.server.logger.Error("internal", "bad dline cidr", err.Error())
				return true
			}

			// load ban info
			var info IPBanInfo
			err = json.Unmarshal([]byte(value), &info)
			if err != nil {
				dm.server.logger.Error("internal", "bad dline data", err.Error())
				return true
			}

			// set opername if it isn't already set
			if info.OperName == "" {
				info.OperName = dm.server.name
			}

			// add to the server
			dm.addNetworkInternal(hostNet, info)

			return true
		})
		return nil
	})
}

func (s *Server) loadDLines() {
	s.dlines = NewDLineManager(s)
}
