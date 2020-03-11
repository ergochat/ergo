// Copyright (c) 2016-2019 Daniel Oaks <daniel@danieloaks.net>
// Copyright (c) 2018-2019 Shivaram Lingamneni <slingamn@cs.stanford.edu>

// released under the ISC license

package ircmsg

import (
	"bytes"
	"errors"
	"strings"
)

const (
	// "The size limit for message tags is 8191 bytes, including the leading
	//  '@' (0x40) and trailing space ' ' (0x20) characters."
	MaxlenTags = 8191

	// MaxlenTags - ('@' + ' ')
	MaxlenTagData = MaxlenTags - 2

	// "Clients MUST NOT send messages with tag data exceeding 4094 bytes,
	//  this includes tags with or without the client-only prefix."
	MaxlenClientTagData = 4094

	// "Servers MUST NOT add tag data exceeding 4094 bytes to messages."
	MaxlenServerTagData = 4094

	// '@' + MaxlenClientTagData + ' '
	// this is the analogue of MaxlenTags when the source of the message is a client
	MaxlenTagsFromClient = MaxlenClientTagData + 2
)

var (
	// ErrorLineIsEmpty indicates that the given IRC line was empty.
	ErrorLineIsEmpty = errors.New("Line is empty")
	// ErrorLineContainsBadChar indicates that the line contained invalid characters
	ErrorLineContainsBadChar = errors.New("Line contains invalid characters")
	// ErrorLineTooLong indicates that the message exceeded the maximum tag length
	// (the name references 417 ERR_INPUTTOOLONG; we reserve the right to return it
	// for messages that exceed the non-tag length limit)
	ErrorLineTooLong = errors.New("Line could not be parsed because a specified length limit was exceeded")

	ErrorCommandMissing = errors.New("IRC messages MUST have a command")
	ErrorBadParam       = errors.New("Cannot have an empty param, a param with spaces, or a param that starts with ':' before the last parameter")
)

// IrcMessage represents an IRC message, as defined by the RFCs and as
// extended by the IRCv3 Message Tags specification with the introduction
// of message tags.
type IrcMessage struct {
	Prefix         string
	Command        string
	Params         []string
	forceTrailing  bool
	tags           map[string]string
	clientOnlyTags map[string]string
}

// ForceTrailing ensures that when the message is serialized, the final parameter
// will be encoded as a "trailing parameter" (preceded by a colon). This is
// almost never necessary and should not be used except when having to interact
// with broken implementations that don't correctly interpret IRC messages.
func (msg *IrcMessage) ForceTrailing() {
	msg.forceTrailing = true
}

// GetTag returns whether a tag is present, and if so, what its value is.
func (msg *IrcMessage) GetTag(tagName string) (present bool, value string) {
	if len(tagName) == 0 {
		return
	} else if tagName[0] == '+' {
		value, present = msg.clientOnlyTags[tagName]
		return
	} else {
		value, present = msg.tags[tagName]
		return
	}
}

// HasTag returns whether a tag is present.
func (msg *IrcMessage) HasTag(tagName string) (present bool) {
	present, _ = msg.GetTag(tagName)
	return
}

// SetTag sets a tag.
func (msg *IrcMessage) SetTag(tagName, tagValue string) {
	if len(tagName) == 0 {
		return
	} else if tagName[0] == '+' {
		if msg.clientOnlyTags == nil {
			msg.clientOnlyTags = make(map[string]string)
		}
		msg.clientOnlyTags[tagName] = tagValue
	} else {
		if msg.tags == nil {
			msg.tags = make(map[string]string)
		}
		msg.tags[tagName] = tagValue
	}
}

// DeleteTag deletes a tag.
func (msg *IrcMessage) DeleteTag(tagName string) {
	if len(tagName) == 0 {
		return
	} else if tagName[0] == '+' {
		delete(msg.clientOnlyTags, tagName)
	} else {
		delete(msg.tags, tagName)
	}
}

// UpdateTags is a convenience to set multiple tags at once.
func (msg *IrcMessage) UpdateTags(tags map[string]string) {
	for name, value := range tags {
		msg.SetTag(name, value)
	}
}

// AllTags returns all tags as a single map.
func (msg *IrcMessage) AllTags() (result map[string]string) {
	result = make(map[string]string, len(msg.tags)+len(msg.clientOnlyTags))
	for name, value := range msg.tags {
		result[name] = value
	}
	for name, value := range msg.clientOnlyTags {
		result[name] = value
	}
	return
}

// ClientOnlyTags returns the client-only tags (the tags with the + prefix).
// The returned map may be internal storage of the IrcMessage object and
// should not be modified.
func (msg *IrcMessage) ClientOnlyTags() map[string]string {
	return msg.clientOnlyTags
}

// ParseLine creates and returns a message from the given IRC line.
func ParseLine(line string) (ircmsg IrcMessage, err error) {
	return parseLine(line, 0, 0)
}

// ParseLineStrict creates and returns an IrcMessage from the given IRC line,
// taking the maximum length into account and truncating the message as appropriate.
// If fromClient is true, it enforces the client limit on tag data length (4094 bytes),
// allowing the server to return ERR_INPUTTOOLONG as appropriate. If truncateLen is
// nonzero, it is the length at which the non-tag portion of the message is truncated.
func ParseLineStrict(line string, fromClient bool, truncateLen int) (ircmsg IrcMessage, err error) {
	maxTagDataLength := MaxlenTagData
	if fromClient {
		maxTagDataLength = MaxlenClientTagData
	}
	return parseLine(line, maxTagDataLength, truncateLen)
}

// slice off any amount of ' ' from the front of the string
func trimInitialSpaces(str string) string {
	var i int
	for i = 0; i < len(str) && str[i] == ' '; i += 1 {
	}
	return str[i:]
}

func parseLine(line string, maxTagDataLength int, truncateLen int) (ircmsg IrcMessage, err error) {
	if strings.IndexByte(line, '\x00') != -1 {
		err = ErrorLineContainsBadChar
		return
	}

	// trim to the first appearance of either '\r' or '\n':
	lineEnd := strings.IndexByte(line, '\r')
	newlineIndex := strings.IndexByte(line, '\n')
	if newlineIndex != -1 && (lineEnd == -1 || newlineIndex < lineEnd) {
		lineEnd = newlineIndex
	}
	if lineEnd != -1 {
		line = line[:lineEnd]
	}

	if len(line) < 1 {
		return ircmsg, ErrorLineIsEmpty
	}

	// tags
	if line[0] == '@' {
		tagEnd := strings.IndexByte(line, ' ')
		if tagEnd == -1 {
			return ircmsg, ErrorLineIsEmpty
		}
		tags := line[1:tagEnd]
		if 0 < maxTagDataLength && maxTagDataLength < len(tags) {
			return ircmsg, ErrorLineTooLong
		}
		err = ircmsg.parseTags(tags)
		if err != nil {
			return
		}
		// skip over the tags and the separating space
		line = line[tagEnd+1:]
	}

	// truncate if desired
	if 0 < truncateLen && truncateLen < len(line) {
		line = line[:truncateLen]
	}

	// modern: "These message parts, and parameters themselves, are separated
	// by one or more ASCII SPACE characters"
	line = trimInitialSpaces(line)

	// prefix
	if 0 < len(line) && line[0] == ':' {
		prefixEnd := strings.IndexByte(line, ' ')
		if prefixEnd == -1 {
			return ircmsg, ErrorLineIsEmpty
		}
		ircmsg.Prefix = line[1:prefixEnd]
		// skip over the prefix and the separating space
		line = line[prefixEnd+1:]
	}

	line = trimInitialSpaces(line)

	// command
	commandEnd := strings.IndexByte(line, ' ')
	paramStart := commandEnd + 1
	if commandEnd == -1 {
		commandEnd = len(line)
		paramStart = len(line)
	}
	// normalize command to uppercase:
	ircmsg.Command = strings.ToUpper(line[:commandEnd])
	if len(ircmsg.Command) == 0 {
		return ircmsg, ErrorLineIsEmpty
	}
	line = line[paramStart:]

	for {
		line = trimInitialSpaces(line)
		if len(line) == 0 {
			break
		}
		// handle trailing
		if line[0] == ':' {
			ircmsg.Params = append(ircmsg.Params, line[1:])
			break
		}
		paramEnd := strings.IndexByte(line, ' ')
		if paramEnd == -1 {
			ircmsg.Params = append(ircmsg.Params, line)
			break
		}
		ircmsg.Params = append(ircmsg.Params, line[:paramEnd])
		line = line[paramEnd+1:]
	}

	return ircmsg, nil
}

// helper to parse tags
func (ircmsg *IrcMessage) parseTags(tags string) (err error) {
	for 0 < len(tags) {
		tagEnd := strings.IndexByte(tags, ';')
		endPos := tagEnd
		nextPos := tagEnd + 1
		if tagEnd == -1 {
			endPos = len(tags)
			nextPos = len(tags)
		}
		tagPair := tags[:endPos]
		equalsIndex := strings.IndexByte(tagPair, '=')
		var tagName, tagValue string
		if equalsIndex == -1 {
			// tag with no value
			tagName = tagPair
		} else {
			tagName, tagValue = tagPair[:equalsIndex], tagPair[equalsIndex+1:]
		}
		ircmsg.SetTag(tagName, UnescapeTagValue(tagValue))
		// skip over the tag just processed, plus the delimiting ; if any
		tags = tags[nextPos:]
	}
	return nil
}

// MakeMessage provides a simple way to create a new IrcMessage.
func MakeMessage(tags map[string]string, prefix string, command string, params ...string) (ircmsg IrcMessage) {
	ircmsg.Prefix = prefix
	ircmsg.Command = command
	ircmsg.Params = params
	ircmsg.UpdateTags(tags)
	return ircmsg
}

// Line returns a sendable line created from an IrcMessage.
func (ircmsg *IrcMessage) Line() (result string, err error) {
	bytes, err := ircmsg.line(0, 0, 0, 0)
	if err == nil {
		result = string(bytes)
	}
	return
}

// LineBytes returns a sendable line created from an IrcMessage.
func (ircmsg *IrcMessage) LineBytes() (result []byte, err error) {
	result, err = ircmsg.line(0, 0, 0, 0)
	return
}

// LineBytesStrict returns a sendable line, as a []byte, created from an IrcMessage.
// fromClient controls whether the server-side or client-side tag length limit
// is enforced. If truncateLen is nonzero, it is the length at which the
// non-tag portion of the message is truncated.
func (ircmsg *IrcMessage) LineBytesStrict(fromClient bool, truncateLen int) ([]byte, error) {
	var tagLimit, clientOnlyTagDataLimit, serverAddedTagDataLimit int
	if fromClient {
		// enforce client max tags:
		// <client_max>   (4096)  :: '@' <tag_data 4094> ' '
		tagLimit = MaxlenTagsFromClient
	} else {
		// on the server side, enforce separate client-only and server-added tag budgets:
		// "Servers MUST NOT add tag data exceeding 4094 bytes to messages."
		// <combined_max> (8191)  :: '@' <tag_data 4094> ';' <tag_data 4094> ' '
		clientOnlyTagDataLimit = MaxlenClientTagData
		serverAddedTagDataLimit = MaxlenServerTagData
	}
	return ircmsg.line(tagLimit, clientOnlyTagDataLimit, serverAddedTagDataLimit, truncateLen)
}

func paramRequiresTrailing(param string) bool {
	return len(param) == 0 || strings.IndexByte(param, ' ') != -1 || param[0] == ':'
}

// line returns a sendable line created from an IrcMessage.
func (ircmsg *IrcMessage) line(tagLimit, clientOnlyTagDataLimit, serverAddedTagDataLimit, truncateLen int) ([]byte, error) {
	if len(ircmsg.Command) < 1 {
		return nil, ErrorCommandMissing
	}

	var buf bytes.Buffer

	// write the tags, computing the budgets for client-only tags and regular tags
	var lenRegularTags, lenClientOnlyTags, lenTags int
	if 0 < len(ircmsg.tags) || 0 < len(ircmsg.clientOnlyTags) {
		buf.WriteByte('@')
		firstTag := true
		writeTags := func(tags map[string]string) {
			for tag, val := range tags {
				if !firstTag {
					buf.WriteByte(';') // delimiter
				}
				buf.WriteString(tag)
				if val != "" {
					buf.WriteByte('=')
					buf.WriteString(EscapeTagValue(val))
				}
				firstTag = false
			}
		}
		writeTags(ircmsg.tags)
		lenRegularTags = buf.Len() - 1 // '@' is not counted
		writeTags(ircmsg.clientOnlyTags)
		lenClientOnlyTags = (buf.Len() - 1) - lenRegularTags // '@' is not counted
		if lenRegularTags != 0 {
			// semicolon between regular and client-only tags is not counted
			lenClientOnlyTags -= 1
		}
		buf.WriteByte(' ')
	}
	lenTags = buf.Len()

	if 0 < tagLimit && tagLimit < buf.Len() {
		return nil, ErrorLineTooLong
	}
	if (0 < clientOnlyTagDataLimit && clientOnlyTagDataLimit < lenClientOnlyTags) || (0 < serverAddedTagDataLimit && serverAddedTagDataLimit < lenRegularTags) {
		return nil, ErrorLineTooLong
	}

	if len(ircmsg.Prefix) > 0 {
		buf.WriteByte(':')
		buf.WriteString(ircmsg.Prefix)
		buf.WriteByte(' ')
	}

	buf.WriteString(ircmsg.Command)

	for i, param := range ircmsg.Params {
		buf.WriteByte(' ')
		requiresTrailing := paramRequiresTrailing(param)
		lastParam := i == len(ircmsg.Params)-1
		if (requiresTrailing || ircmsg.forceTrailing) && lastParam {
			buf.WriteByte(':')
		} else if requiresTrailing && !lastParam {
			return nil, ErrorBadParam
		}
		buf.WriteString(param)
	}

	// truncate if desired
	// -2 for \r\n
	restLen := buf.Len() - lenTags
	if 0 < truncateLen && (truncateLen-2) < restLen {
		buf.Truncate(lenTags + (truncateLen - 2))
	}
	buf.WriteString("\r\n")

	result := buf.Bytes()
	if bytes.IndexByte(result, '\x00') != -1 {
		return nil, ErrorLineContainsBadChar
	}
	return result, nil
}
