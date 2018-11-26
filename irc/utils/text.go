// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package utils

import "bytes"

// WordWrap wraps the given text into a series of lines that don't exceed lineWidth characters.
func WordWrap(text string, lineWidth int) []string {
	var lines []string
	var cacheLine, cacheWord bytes.Buffer

	for _, char := range text {
		if char == '\r' {
			continue
		} else if char == '\n' {
			cacheLine.Write(cacheWord.Bytes())
			lines = append(lines, cacheLine.String())
			cacheWord.Reset()
			cacheLine.Reset()
		} else if (char == ' ' || char == '-') && cacheLine.Len()+cacheWord.Len()+1 < lineWidth {
			// natural word boundary
			cacheLine.Write(cacheWord.Bytes())
			cacheLine.WriteRune(char)
			cacheWord.Reset()
		} else if lineWidth <= cacheLine.Len()+cacheWord.Len()+1 {
			// time to wrap to next line
			if cacheLine.Len() < (lineWidth / 2) {
				// this word takes up more than half a line... just split in the middle of the word
				cacheLine.Write(cacheWord.Bytes())
				cacheLine.WriteRune(char)
				cacheWord.Reset()
			} else {
				cacheWord.WriteRune(char)
			}
			lines = append(lines, cacheLine.String())
			cacheLine.Reset()
		} else {
			// normal character
			cacheWord.WriteRune(char)
		}
	}
	if 0 < cacheWord.Len() {
		cacheLine.Write(cacheWord.Bytes())
	}
	if 0 < cacheLine.Len() {
		lines = append(lines, cacheLine.String())
	}

	return lines
}

// SplitMessage represents a message that's been split for sending.
type SplitMessage struct {
	Original string
	Wrapped  []string // if this is nil, Original didn't need wrapping and can be sent to anyone
}

func MakeSplitMessage(original string, origIs512 bool) (result SplitMessage) {
	result.Original = original

	if !origIs512 {
		result.Wrapped = WordWrap(original, 400)
	}

	return
}
