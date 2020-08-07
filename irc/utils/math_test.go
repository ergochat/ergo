// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import (
	"testing"
)

func TestRoundUp(t *testing.T) {
	assertEqual(RoundUpToPowerOfTwo(2), 2, t)
	assertEqual(RoundUpToPowerOfTwo(3), 4, t)
	assertEqual(RoundUpToPowerOfTwo(64), 64, t)
	assertEqual(RoundUpToPowerOfTwo(65), 128, t)
	assertEqual(RoundUpToPowerOfTwo(100), 128, t)
	assertEqual(RoundUpToPowerOfTwo(1000), 1024, t)
	assertEqual(RoundUpToPowerOfTwo(1025), 2048, t)
	assertEqual(RoundUpToPowerOfTwo(269435457), 536870912, t)
}
