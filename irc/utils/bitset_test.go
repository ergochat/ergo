// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import "testing"

type testBitset [2]uint64

func TestSets(t *testing.T) {
	var t1 testBitset
	t1s := t1[:]
	BitsetInitialize(t1s)

	if BitsetGet(t1s, 0) || BitsetGet(t1s, 63) || BitsetGet(t1s, 64) || BitsetGet(t1s, 127) {
		t.Error("no bits should be set in a newly initialized bitset")
	}

	var i uint
	for i = 0; i < 128; i++ {
		if i%2 == 0 {
			if !BitsetSet(t1s, i, true) {
				t.Error("setting an uninitialized bit should return true")
			}
		}
	}

	if BitsetSet(t1s, 24, true) {
		t.Error("setting an already-set bit should return false")
	}

	if !(BitsetGet(t1s, 0) && !BitsetGet(t1s, 1) && BitsetGet(t1s, 64) && BitsetGet(t1s, 72) && !BitsetGet(t1s, 127)) {
		t.Error("exactly the even-numbered bits should be set")
	}

	if !BitsetSet(t1s, 72, false) {
		t.Error("removing a set bit should return true")
	}

	if BitsetGet(t1s, 72) {
		t.Error("remove doesn't work")
	}

	if BitsetSet(t1s, 72, false) {
		t.Error("removing an unset bit should return false")
	}

	var t2 testBitset
	t2s := t2[:]
	BitsetInitialize(t2s)

	for i = 0; i < 128; i++ {
		if i%2 == 1 {
			BitsetSet(t2s, i, true)
		}
	}

	BitsetUnion(t1s, t2s)
	for i = 0; i < 128; i++ {
		expected := (i != 72)
		if BitsetGet(t1s, i) != expected {
			t.Error("all bits should be set except 72")
		}
	}
}
