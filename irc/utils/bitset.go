// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import "sync/atomic"

// Library functions for lock-free bitsets, typically (constant-sized) arrays of uint32.
// For examples of use, see caps.Set and modes.ModeSet; the array has to be converted to a
// slice to use these functions.

// BitsetGet returns whether a given bit of the bitset is set.
func BitsetGet(set []uint32, position uint) bool {
	idx := position / 32
	bit := position % 32
	block := atomic.LoadUint32(&set[idx])
	return (block & (1 << bit)) != 0
}

// BitsetGetLocal returns whether a given bit of the bitset is set,
// without synchronization.
func BitsetGetLocal(set []uint32, position uint) bool {
	idx := position / 32
	bit := position % 32
	return (set[idx] & (1 << bit)) != 0
}

// BitsetSet sets a given bit of the bitset to 0 or 1, returning whether it changed.
func BitsetSet(set []uint32, position uint, on bool) (changed bool) {
	idx := position / 32
	bit := position % 32
	addr := &set[idx]
	var mask uint32
	mask = 1 << bit
	for {
		current := atomic.LoadUint32(addr)
		var desired uint32
		if on {
			desired = current | mask
		} else {
			desired = current & (^mask)
		}
		if current == desired {
			return false
		} else if atomic.CompareAndSwapUint32(addr, current, desired) {
			return true
		}
	}
}

// BitsetClear clears the bitset in-place.
func BitsetClear(set []uint32) {
	for i := 0; i < len(set); i++ {
		atomic.StoreUint32(&set[i], 0)
	}
}

// BitsetEmpty returns whether the bitset is empty.
// This has false positives under concurrent modification (i.e., it can return true
// even though w.r.t. the sequence of atomic modifications, there was no point at
// which the bitset was completely empty), but that's not how we're using this method.
func BitsetEmpty(set []uint32) (empty bool) {
	for i := 0; i < len(set); i++ {
		if atomic.LoadUint32(&set[i]) != 0 {
			return false
		}
	}
	return true
}

// BitsetUnion modifies `set` to be the union of `set` and `other`.
// This has race conditions in that we don't necessarily get a single
// consistent view of `other` across word boundaries.
func BitsetUnion(set []uint32, other []uint32) {
	for i := 0; i < len(set); i++ {
		for {
			ourAddr := &set[i]
			ourBlock := atomic.LoadUint32(ourAddr)
			otherBlock := atomic.LoadUint32(&other[i])
			newBlock := ourBlock | otherBlock
			if atomic.CompareAndSwapUint32(ourAddr, ourBlock, newBlock) {
				break
			}
		}
	}
}

// BitsetCopy copies the contents of `other` over `set`.
// Similar caveats about race conditions as with `BitsetUnion` apply.
func BitsetCopy(set []uint32, other []uint32) {
	for i := 0; i < len(set); i++ {
		data := atomic.LoadUint32(&other[i])
		atomic.StoreUint32(&set[i], data)
	}
}

// BitsetCopyLocal copies the contents of `other` over `set`,
// without synchronizing the writes to `set`.
func BitsetCopyLocal(set []uint32, other []uint32) {
	for i := 0; i < len(set); i++ {
		data := atomic.LoadUint32(&other[i])
		set[i] = data
	}
}

// BitsetSubtract modifies `set` to subtract the contents of `other`.
// Similar caveats about race conditions as with `BitsetUnion` apply.
func BitsetSubtract(set []uint32, other []uint32) {
	for i := 0; i < len(set); i++ {
		for {
			ourAddr := &set[i]
			ourBlock := atomic.LoadUint32(ourAddr)
			otherBlock := atomic.LoadUint32(&other[i])
			newBlock := ourBlock & (^otherBlock)
			if atomic.CompareAndSwapUint32(ourAddr, ourBlock, newBlock) {
				break
			}
		}
	}
}
