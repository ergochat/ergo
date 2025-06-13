package utils

import "iter"

func ChunkifyParams(params iter.Seq[string], maxChars int) [][]string {
	var chunked [][]string

	var acc []string
	var length = 0

	for p := range params {
		length = length + len(p) + 1 // (accounting for the space)

		if length > maxChars {
			chunked = append(chunked, acc)
			acc = []string{}
			length = 0
		}

		acc = append(acc, p)
	}

	if len(acc) != 0 {
		chunked = append(chunked, acc)
	}

	return chunked
}
