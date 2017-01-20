// written by Daniel Oaks <daniel@danieloaks.net>
// released under the ISC license

package ircmsg

import "strings"

var (
	// valtoescape replaces real characters with message tag escapes.
	valtoescape = strings.NewReplacer("\\", "\\\\", ";", "\\:", " ", "\\s", "\r", "\\r", "\n", "\\n")

	// escapetoval contains the IRCv3 Tag Escapes and how they map to characters.
	escapetoval = map[byte]byte{
		':':  ';',
		's':  ' ',
		'\\': '\\',
		'r':  '\r',
		'n':  '\n',
	}
)

// EscapeTagValue takes a value, and returns an escaped message tag value.
//
// This function is automatically used when lines are created from an
// IrcMessage, so you don't need to call it yourself before creating a line.
func EscapeTagValue(in string) string {
	return valtoescape.Replace(in)
}

// UnescapeTagValue takes an escaped message tag value, and returns the raw value.
//
// This function is automatically used when lines are interpreted by ParseLine,
// so you don't need to call it yourself after parsing a line.
func UnescapeTagValue(in string) string {
	out := ""

	for len(in) > 0 {
		if in[0] == '\\' && len(in) > 1 {
			val, exists := escapetoval[in[1]]
			if exists == true {
				out += string(val)
			} else {
				out += string(in[1])
			}
			in = in[2:]
		} else {
			out += string(in[0])
			in = in[1:]
		}
	}

	return out
}

// TagValue represents the value of a tag. This is because tags may have
// no value at all or just an empty value, and this can represent both
// using the HasValue attribute.
type TagValue struct {
	HasValue bool
	Value    string
}

// NoTagValue returns an empty TagValue.
func NoTagValue() TagValue {
	var tag TagValue
	tag.HasValue = false
	return tag
}

// MakeTagValue returns a TagValue with a defined value.
func MakeTagValue(value string) TagValue {
	var tag TagValue
	tag.HasValue = true
	tag.Value = value
	return tag
}

// MakeTags simplifies tag creation for new messages.
//
// For example: MakeTags("intent", "PRIVMSG", "account", "bunny", "noval", nil)
func MakeTags(values ...interface{}) *map[string]TagValue {
	var tags map[string]TagValue
	tags = make(map[string]TagValue)

	for len(values) > 1 {
		tag := values[0].(string)
		value := values[1]
		var val TagValue

		if value == nil {
			val = NoTagValue()
		} else {
			val = MakeTagValue(value.(string))
		}

		tags[tag] = val

		values = values[2:]
	}

	return &tags
}
