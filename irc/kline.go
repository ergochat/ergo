// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/buntdb"

	"github.com/ergochat/ergo/irc/kv"
	"github.com/ergochat/ergo/irc/utils"
)

const (
	keyKlineEntry = "bans.klinev2 %s"
)

// KLineInfo contains the address itself and expiration time for a given network.
type KLineInfo struct {
	// Mask that is blocked.
	Mask string
	// Matcher, to facilitate fast matching.
	Matcher *regexp.Regexp
	// Info contains information on the ban.
	Info IPBanInfo
}

// KLineManager manages and klines.
type KLineManager struct {
	sync.RWMutex                // tier 1
	persistenceMutex sync.Mutex // tier 2
	// kline'd entries
	entries          map[string]KLineInfo
	expirationTimers map[string]*time.Timer
	server           *Server
}

// NewKLineManager returns a new KLineManager.
func NewKLineManager(s *Server) *KLineManager {
	var km KLineManager
	km.entries = make(map[string]KLineInfo)
	km.expirationTimers = make(map[string]*time.Timer)
	km.server = s

	km.loadFromDatastore()

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
func (km *KLineManager) AddMask(mask string, duration time.Duration, reason, operReason, operName string) error {
	km.persistenceMutex.Lock()
	defer km.persistenceMutex.Unlock()

	info := IPBanInfo{
		Reason:      reason,
		OperReason:  operReason,
		OperName:    operName,
		TimeCreated: time.Now().UTC(),
		Duration:    duration,
	}
	km.addMaskInternal(mask, info)
	return km.persistKLine(mask, info)
}

func (km *KLineManager) addMaskInternal(mask string, info IPBanInfo) {
	re, err := utils.CompileGlob(mask, false)
	// this is validated externally and shouldn't fail regardless
	if err != nil {
		return
	}
	kln := KLineInfo{
		Mask:    mask,
		Matcher: re,
		Info:    info,
	}

	var timeLeft time.Duration
	if info.Duration > 0 {
		timeLeft = info.timeLeft()
		if timeLeft <= 0 {
			return
		}
	}

	km.Lock()
	defer km.Unlock()

	km.entries[mask] = kln
	km.cancelTimer(mask)

	if info.Duration == 0 {
		return
	}

	// set up new expiration timer
	timeCreated := info.TimeCreated
	processExpiration := func() {
		km.Lock()
		defer km.Unlock()

		maskBan, ok := km.entries[mask]
		if ok && maskBan.Info.TimeCreated.Equal(timeCreated) {
			delete(km.entries, mask)
			delete(km.expirationTimers, mask)
		}
	}
	km.expirationTimers[mask] = time.AfterFunc(timeLeft, processExpiration)
}

func (km *KLineManager) cancelTimer(id string) {
	oldTimer := km.expirationTimers[id]
	if oldTimer != nil {
		oldTimer.Stop()
		delete(km.expirationTimers, id)
	}
}

func (km *KLineManager) persistKLine(mask string, info IPBanInfo) error {
	// save in datastore
	klineKey := fmt.Sprintf(keyKlineEntry, mask)
	// assemble json from ban info
	b, err := json.Marshal(info)
	if err != nil {
		return err
	}
	bstr := string(b)
	var setOptions *buntdb.SetOptions
	if info.Duration != 0 {
		setOptions = &buntdb.SetOptions{Expires: true, TTL: info.Duration}
	}

	err = km.server.store.Update(func(tx kv.Tx) error {
		_, _, err := tx.Set(klineKey, bstr, setOptions)
		return err
	})

	return err

}

func (km *KLineManager) unpersistKLine(mask string) error {
	// save in datastore
	klineKey := fmt.Sprintf(keyKlineEntry, mask)
	return km.server.store.Update(func(tx kv.Tx) error {
		_, err := tx.Delete(klineKey)
		return err
	})
}

// RemoveMask removes a mask from the blocked list.
func (km *KLineManager) RemoveMask(mask string) error {
	km.persistenceMutex.Lock()
	defer km.persistenceMutex.Unlock()

	present := func() bool {
		km.Lock()
		defer km.Unlock()
		_, ok := km.entries[mask]
		if ok {
			delete(km.entries, mask)
		}
		km.cancelTimer(mask)
		return ok
	}()

	if !present {
		return errNoExistingBan
	}

	return km.unpersistKLine(mask)
}

func (km *KLineManager) ContainsMask(mask string) (isBanned bool, info IPBanInfo) {
	km.RLock()
	defer km.RUnlock()

	klineInfo, isBanned := km.entries[mask]
	if isBanned {
		info = klineInfo.Info
	}
	return
}

// CheckMasks returns whether or not the hostmask(s) are banned, and how long they are banned for.
func (km *KLineManager) CheckMasks(masks ...string) (isBanned bool, info IPBanInfo) {
	km.RLock()
	defer km.RUnlock()

	for _, entryInfo := range km.entries {
		for _, mask := range masks {
			if entryInfo.Matcher.MatchString(mask) {
				return true, entryInfo.Info
			}
		}
	}

	// no matches!
	isBanned = false
	return
}

func (km *KLineManager) loadFromDatastore() {
	// load from datastore
	klinePrefix := fmt.Sprintf(keyKlineEntry, "")
	km.server.store.View(func(tx kv.Tx) error {
		tx.AscendGreaterOrEqual("", klinePrefix, func(key, value string) bool {
			if !strings.HasPrefix(key, klinePrefix) {
				return false
			}

			// get address name
			mask := strings.TrimPrefix(key, klinePrefix)

			// load ban info
			var info IPBanInfo
			err := json.Unmarshal([]byte(value), &info)
			if err != nil {
				km.server.logger.Error("internal", "couldn't unmarshal kline", err.Error())
				return true
			}

			// add oper name if it doesn't exist already
			if info.OperName == "" {
				info.OperName = km.server.name
			}

			// add to the server
			km.addMaskInternal(mask, info)

			return true
		})
		return nil
	})

}

func (s *Server) loadKLines() {
	s.klines = NewKLineManager(s)
}
