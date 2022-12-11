// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016-2018 Daniel Oaks
// Copyright (c) 2019-2020 Shivaram Lingamneni
// released under the MIT license

package irc

import (
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ergochat/ergo/irc/utils"
)

type MaskInfo struct {
	TimeCreated     time.Time
	CreatorNickmask string
	CreatorAccount  string
}

// UserMaskSet holds a set of client masks and lets you match  hostnames to them.
type UserMaskSet struct {
	sync.RWMutex
	serialCacheUpdateMutex sync.Mutex
	masks                  map[string]MaskInfo
	regexp                 atomic.Pointer[regexp.Regexp]
	muteRegexp             atomic.Pointer[regexp.Regexp]
}

func NewUserMaskSet() *UserMaskSet {
	return new(UserMaskSet)
}

// Add adds the given mask to this set.
func (set *UserMaskSet) Add(mask, creatorNickmask, creatorAccount string) (maskAdded string, err error) {
	casefoldedMask, err := CanonicalizeMaskWildcard(mask)
	if err != nil {
		return
	}

	set.serialCacheUpdateMutex.Lock()
	defer set.serialCacheUpdateMutex.Unlock()

	set.Lock()
	if set.masks == nil {
		set.masks = make(map[string]MaskInfo)
	}
	_, present := set.masks[casefoldedMask]
	if !present {
		maskAdded = casefoldedMask
		set.masks[casefoldedMask] = MaskInfo{
			TimeCreated:     time.Now().UTC(),
			CreatorNickmask: creatorNickmask,
			CreatorAccount:  creatorAccount,
		}
	}
	set.Unlock()

	if !present {
		set.setRegexp()
	}
	return
}

// Remove removes the given mask from this set.
func (set *UserMaskSet) Remove(mask string) (maskRemoved string, err error) {
	mask, err = CanonicalizeMaskWildcard(mask)
	if err != nil {
		return
	}

	set.serialCacheUpdateMutex.Lock()
	defer set.serialCacheUpdateMutex.Unlock()

	set.Lock()
	_, removed := set.masks[mask]
	if removed {
		maskRemoved = mask
		delete(set.masks, mask)
	}
	set.Unlock()

	if removed {
		set.setRegexp()
	}
	return
}

func (set *UserMaskSet) SetMasks(masks map[string]MaskInfo) {
	set.Lock()
	set.masks = masks
	set.Unlock()
	set.setRegexp()
}

func (set *UserMaskSet) Masks() (result map[string]MaskInfo) {
	set.RLock()
	defer set.RUnlock()

	result = make(map[string]MaskInfo, len(set.masks))
	for mask, info := range set.masks {
		result[mask] = info
	}
	return
}

// Match matches the given n!u@h against the standard (non-ext) bans.
func (set *UserMaskSet) Match(userhost string) bool {
	regexp := set.regexp.Load()

	if regexp == nil {
		return false
	}
	return regexp.MatchString(userhost)
}

// MatchMute matches the given NUH against the mute extbans.
func (set *UserMaskSet) MatchMute(userhost string) bool {
	regexp := set.MuteRegexp()

	if regexp == nil {
		return false
	}
	return regexp.MatchString(userhost)
}

func (set *UserMaskSet) MuteRegexp() *regexp.Regexp {
	return set.muteRegexp.Load()
}

func (set *UserMaskSet) Length() int {
	set.RLock()
	defer set.RUnlock()
	return len(set.masks)
}

func (set *UserMaskSet) setRegexp() {
	set.RLock()
	maskExprs := make([]string, 0, len(set.masks))
	var muteExprs []string
	for mask := range set.masks {
		if strings.HasPrefix(mask, "m:") {
			muteExprs = append(muteExprs, mask[2:])
		} else {
			maskExprs = append(maskExprs, mask)
		}
	}
	set.RUnlock()

	compileMasks := func(masks []string) *regexp.Regexp {
		if len(masks) == 0 {
			return nil
		}
		re, _ := utils.CompileMasks(masks)
		return re
	}

	re := compileMasks(maskExprs)
	muteRe := compileMasks(muteExprs)

	set.regexp.Store(re)
	set.muteRegexp.Store(muteRe)
}
