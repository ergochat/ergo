// written by Daniel Oaks <daniel@danieloaks.net>
// released under the ISC license

package ircmsg

import "bytes"
import "strings"

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
// IrcMessage, so you don't need to call it yourself before creating a line.
func EscapeTagValue(inString string) string {
	return valtoescape.Replace(inString)
}

// UnescapeTagValue takes an escaped message tag value, and returns the raw value.
//
// This function is automatically used when lines are interpreted by ParseLine,
// so you don't need to call it yourself after parsing a line.
func UnescapeTagValue(inString string) string {
	// buf.Len() == 0 is the fastpath where we have not needed to unescape any chars
	var buf bytes.Buffer
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
