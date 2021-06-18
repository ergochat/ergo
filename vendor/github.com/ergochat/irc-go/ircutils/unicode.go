// Copyright (c) 2021 Shivaram Lingamneni
// Released under the MIT License

package ircutils

import (
	"strings"
	"unicode"
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

// Sanitizes human-readable text to make it safe for IRC;
// assumes UTF-8 and uses the replacement character where
// applicable.
func SanitizeText(message string, byteLimit int) (result string) {
	var buf strings.Builder

	for _, r := range message {
		if r == '\x00' || r == '\r' {
			continue
		} else if r == '\n' {
			if buf.Len()+2 <= byteLimit {
				buf.WriteString("  ")
				continue
			} else {
				break
			}
		} else if unicode.IsSpace(r) {
			if buf.Len()+1 <= byteLimit {
				buf.WriteString(" ")
			} else {
				break
			}
		} else {
			rLen := utf8.RuneLen(r)
			if buf.Len()+rLen <= byteLimit {
				buf.WriteRune(r)
			} else {
				break
			}
		}
	}

	return buf.String()
}
