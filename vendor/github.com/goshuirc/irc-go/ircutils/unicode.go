// Copyright (c) 2021 Shivaram Lingamneni
// Released under the MIT License

package ircutils

import (
	"unicode/utf8"
)

// truncate a message, taking care not to make valid UTF8 into invalid UTF8
func TruncateUTF8Safe(message string, byteLimit int) (result string) {
	if len(message) <= byteLimit {
		return message
	}
	message = message[:byteLimit]
	for i := 0; i < (utf8.UTFMax - 1); i++ {
		r, n := utf8.DecodeLastRuneInString(message)
		if r == utf8.RuneError && n <= 1 {
			message = message[:len(message)-1]
		} else {
			break
		}
	}
	return message
}
