// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package utils

import (
	"strings"
	"time"
)

func IsRestrictedCTCPMessage(message string) bool {
	// block all CTCP privmsgs to Tor clients except for ACTION
	// DCC can potentially be used for deanonymization, the others for fingerprinting
	return strings.HasPrefix(message, "\x01") && !strings.HasPrefix(message, "\x01ACTION")
}

type MessagePair struct {
	Message string
	Concat  bool // should be relayed with the multiline-concat tag
}

// SplitMessage represents a message that's been split for sending.
// Two possibilities:
// (a) Standard message that can be relayed on a single 512-byte line
//
//	(MessagePair contains the message, Split == nil)
//
// (b) multiline message that was split on the client side
//
//	(Message == "", Split contains the split lines)
type SplitMessage struct {
	Message string
	Msgid   string
	Split   []MessagePair
	Time    time.Time
}

func MakeMessage(original string) (result SplitMessage) {
	result.Message = original
	result.Msgid = GenerateSecretToken()
	result.SetTime()

	return
}

func (sm *SplitMessage) Append(message string, concat bool) {
	if sm.Msgid == "" {
		sm.Msgid = GenerateSecretToken()
	}
	sm.Split = append(sm.Split, MessagePair{
		Message: message,
		Concat:  concat,
	})
}

func (sm *SplitMessage) SetTime() {
	// strip the monotonic time, it's a potential source of problems:
	sm.Time = time.Now().UTC().Round(0)
}

func (sm *SplitMessage) LenLines() int {
	if sm.Split == nil {
		if sm.Message == "" {
			return 0
		} else {
			return 1
		}
	}
	return len(sm.Split)
}

func (sm *SplitMessage) ValidMultiline() bool {
	// must contain at least one nonblank line
	for i := 0; i < len(sm.Split); i++ {
		if len(sm.Split[i].Message) != 0 {
			return true
		}
	}
	return false
}

func (sm *SplitMessage) IsRestrictedCTCPMessage() bool {
	if IsRestrictedCTCPMessage(sm.Message) {
		return true
	}
	for i := 0; i < len(sm.Split); i++ {
		if IsRestrictedCTCPMessage(sm.Split[i].Message) {
			return true
		}
	}
	return false
}

func (sm *SplitMessage) Is512() bool {
	return sm.Split == nil
}

// TokenLineBuilder is a helper for building IRC lines composed of delimited tokens,
// with a maximum line length.
type TokenLineBuilder struct {
	lineLen int
	delim   string
	buf     strings.Builder
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

// BuildTokenLines is a convenience to apply TokenLineBuilder to a predetermined
// slice of tokens.
func BuildTokenLines(lineLen int, tokens []string, delim string) []string {
	var tl TokenLineBuilder
	tl.Initialize(lineLen, delim)
	for _, arg := range tokens {
		tl.Add(arg)
	}
	return tl.Lines()
}
