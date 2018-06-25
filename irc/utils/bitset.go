// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import "sync/atomic"

// Library functions for lock-free bitsets, typically (constant-sized) arrays of uint64.
// For examples of use, see caps.Set and modes.ModeSet; the array has to be converted to a
// slice to use these functions.

// BitsetInitialize initializes a bitset.
func BitsetInitialize(set []uint64) {
	// XXX re-zero the bitset using atomic stores. it's unclear whether this is required,
	// however, golang issue #5045 suggests that you shouldn't mix atomic operations
	// with non-atomic operations (such as the runtime's automatic zero-initialization) on
	// the same word
	for i := 0; i < len(set); i++ {
		atomic.StoreUint64(&set[i], 0)
	}
}

// BitsetGet returns whether a given bit of the bitset is set.
func BitsetGet(set []uint64, position uint) bool {
	idx := position / 64
	bit := position % 64
	block := atomic.LoadUint64(&set[idx])
	return (block & (1 << bit)) != 0
}

// BitsetSet sets a given bit of the bitset to 0 or 1, returning whether it changed.
func BitsetSet(set []uint64, position uint, on bool) (changed bool) {
	idx := position / 64
	bit := position % 64
	addr := &set[idx]
	var mask uint64
	mask = 1 << bit
	for {
		current := atomic.LoadUint64(addr)
		previouslyOn := (current & mask) != 0
		if on == previouslyOn {
			return false
		}
		var desired uint64
		if on {
			desired = current | mask
		} else {
			desired = current & (^mask)
		}
		if atomic.CompareAndSwapUint64(addr, current, desired) {
			return true
		}
	}
}

// BitsetEmpty returns whether the bitset is empty.
// Right now, this is technically free of race conditions because we don't
// have a method that can simultaneously modify two bits separated by a word boundary
// such that one of those modifications is an unset. If we did, there would be a race
// that could produce false positives. It's probably better to assume that they are
// already possible under concurrent modification (which is not how we're using this).
func BitsetEmpty(set []uint64) (empty bool) {
	for i := 0; i < len(set); i++ {
		if atomic.LoadUint64(&set[i]) != 0 {
			return false
		}
	}
	return true
}

// BitsetUnion modifies `set` to be the union of `set` and `other`.
// This has race conditions in that we don't necessarily get a single
// consistent view of `other` across word boundaries.
func BitsetUnion(set []uint64, other []uint64) {
	for i := 0; i < len(set); i++ {
		for {
			ourAddr := &set[i]
			ourBlock := atomic.LoadUint64(ourAddr)
			otherBlock := atomic.LoadUint64(&other[i])
			newBlock := ourBlock | otherBlock
			if atomic.CompareAndSwapUint64(ourAddr, ourBlock, newBlock) {
				break
			}
		}
	}
}
