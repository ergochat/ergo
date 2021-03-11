// written by Daniel Oaks <daniel@danieloaks.net>
// released under the ISC license

package ircmsg

import (
	"strings"
	"unicode/utf8"
)

var (
	// valtoescape replaces real characters with message tag escapes.
	valtoescape = strings.NewReplacer("\\", "\\\\", ";", "\\:", " ", "\\s", "\r", "\\r", "\n", "\\n")

	escapedCharLookupTable [256]byte
)

func init() {
	// most chars escape to themselves
	for i := 0; i < 256; i += 1 {
		escapedCharLookupTable[i] = byte(i)
	}
	// these are the exceptions
	escapedCharLookupTable[':'] = ';'
	escapedCharLookupTable['s'] = ' '
	escapedCharLookupTable['r'] = '\r'
	escapedCharLookupTable['n'] = '\n'
}

// EscapeTagValue takes a value, and returns an escaped message tag value.
//
// This function is automatically used when lines are created from an
// Message, so you don't need to call it yourself before creating a line.
func EscapeTagValue(inString string) string {
	return valtoescape.Replace(inString)
}

// UnescapeTagValue takes an escaped message tag value, and returns the raw value.
//
// This function is automatically used when lines are interpreted by ParseLine,
// so you don't need to call it yourself after parsing a line.
func UnescapeTagValue(inString string) string {
	// buf.Len() == 0 is the fastpath where we have not needed to unescape any chars
	var buf strings.Builder
	remainder := inString
	for {
		backslashPos := strings.IndexByte(remainder, '\\')

		if backslashPos == -1 {
			if buf.Len() == 0 {
				return inString
			} else {
				buf.WriteString(remainder)
				break
			}
		} else if backslashPos == len(remainder)-1 {
			// trailing backslash, which we strip
			if buf.Len() == 0 {
				return inString[:len(inString)-1]
			} else {
				buf.WriteString(remainder[:len(remainder)-1])
				break
			}
		}

		// non-trailing backslash detected; we're now on the slowpath
		// where we modify the string
		if buf.Len() == 0 {
			buf.Grow(len(inString)) // just an optimization
		}
		buf.WriteString(remainder[:backslashPos])
		buf.WriteByte(escapedCharLookupTable[remainder[backslashPos+1]])
		remainder = remainder[backslashPos+2:]
	}

	return buf.String()
}

// https://ircv3.net/specs/extensions/message-tags.html#rules-for-naming-message-tags
func validateTagName(name string) bool {
	if len(name) == 0 {
		return false
	}
	if name[0] == '+' {
		name = name[1:]
	}
	if len(name) == 0 {
		return false
	}
	// let's err on the side of leniency here; allow -./ (45-47) in any position
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(('-' <= c && c <= '/') || ('0' <= c && c <= '9') || ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z')) {
			return false
		}
	}
	return true
}

// "Tag values MUST be encoded as UTF8."
func validateTagValue(value string) bool {
	return utf8.ValidString(value)
}
