// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"encoding/json"
	"sync"

	"github.com/goshuirc/irc-go/ircmatch"
	"github.com/tidwall/buntdb"
)

const (
	keyKlineEntry = "bans.kline %s"
)

// KLineInfo contains the address itself and expiration time for a given network.
type KLineInfo struct {
	// Mask that is blocked.
	Mask string
	// Matcher, to facilitate fast matching.
	Matcher ircmatch.Matcher
	// Info contains information on the ban.
	Info IPBanInfo
}

// KLineManager manages and klines.
type KLineManager struct {
	sync.RWMutex // tier 1
	// kline'd entries
	entries map[string]*KLineInfo
}

// NewKLineManager returns a new KLineManager.
func NewKLineManager() *KLineManager {
	var km KLineManager
	km.entries = make(map[string]*KLineInfo)
	return &km
}

// AllBans returns all bans (for use with APIs, etc).
func (km *KLineManager) AllBans() map[string]IPBanInfo {
	allb := make(map[string]IPBanInfo)

	km.RLock()
	defer km.RUnlock()
	for name, info := range km.entries {
		allb[name] = info.Info
	}

	return allb
}

// AddMask adds to the blocked list.
func (km *KLineManager) AddMask(mask string, length *IPRestrictTime, reason, operReason, operName string) {
	kln := KLineInfo{
		Mask:    mask,
		Matcher: ircmatch.MakeMatch(mask),
		Info: IPBanInfo{
			Time:       length,
			Reason:     reason,
			OperReason: operReason,
			OperName:   operName,
		},
	}
	km.Lock()
	km.entries[mask] = &kln
	km.Unlock()
}

// RemoveMask removes a mask from the blocked list.
func (km *KLineManager) RemoveMask(mask string) {
	km.Lock()
	delete(km.entries, mask)
	km.Unlock()
}

// CheckMasks returns whether or not the hostmask(s) are banned, and how long they are banned for.
func (km *KLineManager) CheckMasks(masks ...string) (isBanned bool, info *IPBanInfo) {
	doCleanup := false
	defer func() {
		// asynchronously remove expired bans
		if doCleanup {
			go func() {
				km.Lock()
				defer km.Unlock()
				for key, entry := range km.entries {
					if entry.Info.Time.IsExpired() {
						delete(km.entries, key)
					}
				}
			}()
		}
	}()

	km.RLock()
	defer km.RUnlock()

	for _, entryInfo := range km.entries {
		if entryInfo.Info.Time != nil && entryInfo.Info.Time.IsExpired() {
			doCleanup = true
			continue
		}

		matches := false
		for _, mask := range masks {
			if entryInfo.Matcher.Match(mask) {
				matches = true
				break
			}
		}
		if matches {
			return true, &entryInfo.Info
		}
	}

	// no matches!
	return false, nil
}

func (s *Server) loadKLines() {
	s.klines = NewKLineManager()

	// load from datastore
	s.store.View(func(tx *buntdb.Tx) error {
		//TODO(dan): We could make this safer
		tx.AscendKeys("bans.kline *", func(key, value string) bool {
			// get address name
			key = key[len("bans.kline "):]
			mask := key

			// load ban info
			var info IPBanInfo
			json.Unmarshal([]byte(value), &info)

			// add oper name if it doesn't exist already
			if info.OperName == "" {
				info.OperName = s.name
			}

			// add to the server
			s.klines.AddMask(mask, info.Time, info.Reason, info.OperReason, info.OperName)

			return true // true to continue I guess?
		})
		return nil
	})
}
