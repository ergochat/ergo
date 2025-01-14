// Copyright (c) 2021-2024 Simon Ser <contact@emersion.fr>
// Originally released under the AGPLv3, relicensed to the Ergo project under the MIT license

package webpush

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

func isWordBoundary(r rune) bool {
	switch r {
	case '-', '_', '|': // inspired from weechat.look.highlight_regex
		return false
	default:
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	}
}

func isURIPrefix(text string) bool {
	if i := strings.LastIndexFunc(text, unicode.IsSpace); i >= 0 {
		text = text[i:]
	}

	i := strings.Index(text, "://")
	if i < 0 {
		return false
	}

	// See RFC 3986 section 3
	r, _ := utf8.DecodeLastRuneInString(text[:i])
	switch r {
	case '+', '-', '.':
		return true
	default:
		return ('0' <= r && r <= '9') || ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z')
	}
}

func IsHighlight(text, nick string) bool {
	if len(nick) == 0 {
		return false
	}

	for {
		i := strings.Index(text, nick)
		if i < 0 {
			return false
		}

		left, _ := utf8.DecodeLastRuneInString(text[:i])
		right, _ := utf8.DecodeRuneInString(text[i+len(nick):])
		if isWordBoundary(left) && isWordBoundary(right) && !isURIPrefix(text[:i]) {
			return true
		}

		text = text[i+len(nick):]
	}
}
