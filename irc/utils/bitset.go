// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import "sync/atomic"

// Library functions for lock-free bitsets, typically (constant-sized) arrays of uint64.
// For examples of use, see caps.Set and modes.ModeSet; the array has to be converted to a
// slice to use these functions.

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
		var desired uint64
		if on {
			desired = current | mask
		} else {
			desired = current & (^mask)
		}
		if current == desired {
			return false
		} else if atomic.CompareAndSwapUint64(addr, current, desired) {
			return true
		}
	}
}

// BitsetEmpty returns whether the bitset is empty.
// This has false positives under concurrent modification (i.e., it can return true
// even though w.r.t. the sequence of atomic modifications, there was no point at
// which the bitset was completely empty), but that's not how we're using this method.
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

// BitsetCopy copies the contents of `other` over `set`.
// Similar caveats about race conditions as with `BitsetUnion` apply.
func BitsetCopy(set []uint64, other []uint64) {
	for i := 0; i < len(set); i++ {
		data := atomic.LoadUint64(&other[i])
		atomic.StoreUint64(&set[i], data)
	}
}

// BitsetSubtract modifies `set` to subtract the contents of `other`.
// Similar caveats about race conditions as with `BitsetUnion` apply.
func BitsetSubtract(set []uint64, other []uint64) {
	for i := 0; i < len(set); i++ {
		for {
			ourAddr := &set[i]
			ourBlock := atomic.LoadUint64(ourAddr)
			otherBlock := atomic.LoadUint64(&other[i])
			newBlock := ourBlock & (^otherBlock)
			if atomic.CompareAndSwapUint64(ourAddr, ourBlock, newBlock) {
				break
			}
		}
	}
}
