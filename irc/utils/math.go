// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

// return n such that v <= n and n == 2**i for some i
func RoundUpToPowerOfTwo(v int) int {
	// http://graphics.stanford.edu/~seander/bithacks.html
	v -= 1
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	return v + 1
}
