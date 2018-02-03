// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"encoding/json"

	"github.com/tidwall/buntdb"
)

const (
	keyDlineEntry = "bans.dline %s"
)

var (
	errNoExistingBan = errors.New("Ban does not exist")
)

// IPRestrictTime contains the expiration info about the given IP.
type IPRestrictTime struct {
	// Duration is how long this block lasts for.
	Duration time.Duration `json:"duration"`
	// Expires is when this block expires.
	Expires time.Time `json:"expires"`
}

// IsExpired returns true if the time has expired.
func (iptime *IPRestrictTime) IsExpired() bool {
	return iptime.Expires.Before(time.Now())
}

// IPBanInfo holds info about an IP/net ban.
type IPBanInfo struct {
	// Reason is the ban reason.
	Reason string `json:"reason"`
	// OperReason is an oper ban reason.
	OperReason string `json:"oper_reason"`
	// OperName is the oper who set the ban.
	OperName string `json:"oper_name"`
	// Time holds details about the duration, if it exists.
	Time *IPRestrictTime `json:"time"`
}

// BanMessage returns the ban message.
func (info IPBanInfo) BanMessage(message string) string {
	message = fmt.Sprintf(message, info.Reason)
	if info.Time != nil {
		message += fmt.Sprintf(" [%s]", info.Time.Duration.String())
	}
	return message
}

// dLineAddr contains the address itself and expiration time for a given network.
type dLineAddr struct {
	// Address is the address that is blocked.
	Address net.IP
	// Info contains information on the ban.
	Info IPBanInfo
}

// dLineNet contains the net itself and expiration time for a given network.
type dLineNet struct {
	// Network is the network that is blocked.
	Network net.IPNet
	// Info contains information on the ban.
	Info IPBanInfo
}

// DLineManager manages and dlines.
type DLineManager struct {
	sync.RWMutex // tier 1
	// addresses that are dlined
	addresses map[string]*dLineAddr
	// networks that are dlined
	networks map[string]*dLineNet
}

// NewDLineManager returns a new DLineManager.
func NewDLineManager() *DLineManager {
	var dm DLineManager
	dm.addresses = make(map[string]*dLineAddr)
	dm.networks = make(map[string]*dLineNet)
	return &dm
}

// AllBans returns all bans (for use with APIs, etc).
func (dm *DLineManager) AllBans() map[string]IPBanInfo {
	allb := make(map[string]IPBanInfo)

	dm.RLock()
	defer dm.RUnlock()

	for name, info := range dm.addresses {
		allb[name] = info.Info
	}
	for name, info := range dm.networks {
		allb[name] = info.Info
	}

	return allb
}

// AddNetwork adds a network to the blocked list.
func (dm *DLineManager) AddNetwork(network net.IPNet, length *IPRestrictTime, reason, operReason, operName string) {
	netString := network.String()
	dln := dLineNet{
		Network: network,
		Info: IPBanInfo{
			Time:       length,
			Reason:     reason,
			OperReason: operReason,
			OperName:   operName,
		},
	}
	dm.Lock()
	dm.networks[netString] = &dln
	dm.Unlock()
}

// RemoveNetwork removes a network from the blocked list.
func (dm *DLineManager) RemoveNetwork(network net.IPNet) {
	netString := network.String()
	dm.Lock()
	delete(dm.networks, netString)
	dm.Unlock()
}

// AddIP adds an IP address to the blocked list.
func (dm *DLineManager) AddIP(addr net.IP, length *IPRestrictTime, reason, operReason, operName string) {
	addrString := addr.String()
	dla := dLineAddr{
		Address: addr,
		Info: IPBanInfo{
			Time:       length,
			Reason:     reason,
			OperReason: operReason,
			OperName:   operName,
		},
	}
	dm.Lock()
	dm.addresses[addrString] = &dla
	dm.Unlock()
}

// RemoveIP removes an IP from the blocked list.
func (dm *DLineManager) RemoveIP(addr net.IP) {
	addrString := addr.String()
	dm.Lock()
	delete(dm.addresses, addrString)
	dm.Unlock()
}

// CheckIP returns whether or not an IP address was banned, and how long it is banned for.
func (dm *DLineManager) CheckIP(addr net.IP) (isBanned bool, info *IPBanInfo) {
	// check IP addr
	addrString := addr.String()
	dm.RLock()
	addrInfo := dm.addresses[addrString]
	dm.RUnlock()

	if addrInfo != nil {
		if addrInfo.Info.Time != nil {
			if addrInfo.Info.Time.IsExpired() {
				// ban on IP has expired, remove it from our blocked list
				dm.RemoveIP(addr)
			} else {
				return true, &addrInfo.Info
			}
		} else {
			return true, &addrInfo.Info
		}
	}

	// check networks
	doCleanup := false
	defer func() {
		if doCleanup {
			go func() {
				dm.Lock()
				defer dm.Unlock()
				for key, netInfo := range dm.networks {
					if netInfo.Info.Time.IsExpired() {
						delete(dm.networks, key)
					}
				}
			}()
		}
	}()

	dm.RLock()
	defer dm.RUnlock()

	for _, netInfo := range dm.networks {
		if netInfo.Info.Time != nil && netInfo.Info.Time.IsExpired() {
			// expired ban, ignore and clean up later
			doCleanup = true
		} else if netInfo.Network.Contains(addr) {
			return true, &netInfo.Info
		}
	}
	// no matches!
	return false, nil
}

func (s *Server) loadDLines() {
	s.dlines = NewDLineManager()

	// load from datastore
	s.store.View(func(tx *buntdb.Tx) error {
		//TODO(dan): We could make this safer
		tx.AscendKeys("bans.dline *", func(key, value string) bool {
			// get address name
			key = key[len("bans.dline "):]

			// load addr/net
			var hostAddr net.IP
			var hostNet *net.IPNet
			_, hostNet, err := net.ParseCIDR(key)
			if err != nil {
				hostAddr = net.ParseIP(key)
			}

			// load ban info
			var info IPBanInfo
			json.Unmarshal([]byte(value), &info)

			// set opername if it isn't already set
			if info.OperName == "" {
				info.OperName = s.name
			}

			// add to the server
			if hostNet == nil {
				s.dlines.AddIP(hostAddr, info.Time, info.Reason, info.OperReason, info.OperName)
			} else {
				s.dlines.AddNetwork(*hostNet, info.Time, info.Reason, info.OperReason, info.OperName)
			}

			return true // true to continue I guess?
		})
		return nil
	})
}
