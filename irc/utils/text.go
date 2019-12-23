// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package utils

import (
	"bytes"
	"strings"
	"time"
)

func IsRestrictedCTCPMessage(message string) bool {
	// block all CTCP privmsgs to Tor clients except for ACTION
	// DCC can potentially be used for deanonymization, the others for fingerprinting
	return strings.HasPrefix(message, "\x01") && !strings.HasPrefix(message, "\x01ACTION")
}

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

type MessagePair struct {
	Message string
	Msgid   string
	Concat  bool // should be relayed with the multiline-concat tag
}

// SplitMessage represents a message that's been split for sending.
// Three possibilities:
// (a) Standard message that can be relayed on a single 512-byte line
//     (MessagePair contains the message, Wrapped == nil)
// (b) oragono.io/maxline-2 message that was split on the server side
//     (MessagePair contains the unsplit message, Wrapped contains the split lines)
// (c) multiline message that was split on the client side
//     (MessagePair is zero, Wrapped contains the split lines)
type SplitMessage struct {
	MessagePair
	Wrapped []MessagePair // if this is nil, `Message` didn't need wrapping and can be sent to anyone
	Time    time.Time
}

const defaultLineWidth = 400

func MakeSplitMessage(original string, origIs512 bool) (result SplitMessage) {
	result.Message = original
	result.Msgid = GenerateSecretToken()
	result.Time = time.Now().UTC()

	if !origIs512 && defaultLineWidth < len(original) {
		wrapped := WordWrap(original, defaultLineWidth)
		result.Wrapped = make([]MessagePair, len(wrapped))
		for i, wrappedMessage := range wrapped {
			result.Wrapped[i] = MessagePair{
				Message: wrappedMessage,
				Msgid:   GenerateSecretToken(),
			}
		}
	}

	return
}

func (sm *SplitMessage) Append(message string, concat bool) {
	if sm.Msgid == "" {
		sm.Msgid = GenerateSecretToken()
	}
	sm.Wrapped = append(sm.Wrapped, MessagePair{
		Message: message,
		Msgid:   GenerateSecretToken(),
		Concat:  concat,
	})
}

func (sm *SplitMessage) LenLines() int {
	if sm.Wrapped == nil {
		if (sm.MessagePair == MessagePair{}) {
			return 0
		} else {
			return 1
		}
	}
	return len(sm.Wrapped)
}

func (sm *SplitMessage) LenBytes() (result int) {
	if sm.Wrapped == nil {
		return len(sm.Message)
	}
	for i := 0; i < len(sm.Wrapped); i++ {
		result += len(sm.Wrapped[i].Message)
	}
	return
}

func (sm *SplitMessage) IsRestrictedCTCPMessage() bool {
	if IsRestrictedCTCPMessage(sm.Message) {
		return true
	}
	for i := 0; i < len(sm.Wrapped); i++ {
		if IsRestrictedCTCPMessage(sm.Wrapped[i].Message) {
			return true
		}
	}
	return false
}

func (sm *SplitMessage) IsMultiline() bool {
	return sm.Message == "" && len(sm.Wrapped) != 0
}

func (sm *SplitMessage) Is512() bool {
	return sm.Message != "" && sm.Wrapped == nil
}

// TokenLineBuilder is a helper for building IRC lines composed of delimited tokens,
// with a maximum line length.
type TokenLineBuilder struct {
	lineLen int
	delim   string
	buf     bytes.Buffer
	result  []string
}

func (t *TokenLineBuilder) Initialize(lineLen int, delim string) {
	t.lineLen = lineLen
	t.delim = delim
}

// Add adds a token to the line, creating a new line if necessary.
func (t *TokenLineBuilder) Add(token string) {
	tokenLen := len(token)
	if t.buf.Len() != 0 {
		tokenLen += len(t.delim)
	}
	if t.lineLen < t.buf.Len()+tokenLen {
		t.result = append(t.result, t.buf.String())
		t.buf.Reset()
	}
	if t.buf.Len() != 0 {
		t.buf.WriteString(t.delim)
	}
	t.buf.WriteString(token)
}

// Lines terminates the line-building and returns all the lines.
func (t *TokenLineBuilder) Lines() (result []string) {
	result = t.result
	t.result = nil
	if t.buf.Len() != 0 {
		result = append(result, t.buf.String())
		t.buf.Reset()
	}
	return
}
