// Copyright (c) 2021 Shivaram Lingamneni
// Released under the MIT License

package ircutils

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ergochat/irc-go/ircmsg"
)

var TruncateUTF8Safe = ircmsg.TruncateUTF8Safe

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
