// Copyright (c) 2021 Shivaram Lingamneni
// Released under the MIT License

package ircmsg

import (
	"unicode/utf8"
)

// TruncateUTF8Safe truncates a message, respecting UTF8 boundaries. If a message
// was originally valid UTF8, TruncateUTF8Safe will not make it invalid; instead
// it will truncate additional bytes as needed, back to the last valid
// UTF8-encoded codepoint. If a message is not UTF8, TruncateUTF8Safe will truncate
// at most 3 additional bytes before giving up.
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
