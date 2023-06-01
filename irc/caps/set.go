// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package caps

import (
	"fmt"
	"github.com/ergochat/ergo/irc/utils"
)

// Set holds a set of enabled capabilities.
type Set [bitsetLen]uint32

// Values holds capability values.
type Values map[Capability]string

// NewSet returns a new Set, with the given capabilities enabled.
func NewSet(capabs ...Capability) *Set {
	var newSet Set
	newSet.Enable(capabs...)
	return &newSet
}

// NewCompleteSet returns a new Set, with all defined capabilities enabled.
func NewCompleteSet() *Set {
	var newSet Set
	asSlice := newSet[:]
	for i := 0; i < numCapabs; i += 1 {
		utils.BitsetSet(asSlice, uint(i), true)
	}
	return &newSet
}

// Enable enables the given capabilities.
func (s *Set) Enable(capabs ...Capability) {
	asSlice := s[:]
	for _, capab := range capabs {
		utils.BitsetSet(asSlice, uint(capab), true)
	}
}

// Disable disables the given capabilities.
func (s *Set) Disable(capabs ...Capability) {
	asSlice := s[:]
	for _, capab := range capabs {
		utils.BitsetSet(asSlice, uint(capab), false)
	}
}

// Add adds the given capabilities to this set.
// this is just a wrapper to allow more clear use.
func (s *Set) Add(capabs ...Capability) {
	s.Enable(capabs...)
}

// Remove removes the given capabilities from this set.
// this is just a wrapper to allow more clear use.
func (s *Set) Remove(capabs ...Capability) {
	s.Disable(capabs...)
}

// Has returns true if this set has the given capability.
func (s *Set) Has(capab Capability) bool {
	return utils.BitsetGet(s[:], uint(capab))
}

// HasAll returns true if the set has all the given capabilities.
func (s *Set) HasAll(capabs ...Capability) bool {
	for _, capab := range capabs {
		if !s.Has(capab) {
			return false
		}
	}
	return true
}

// Union adds all the capabilities of another set to this set.
func (s *Set) Union(other *Set) {
	utils.BitsetUnion(s[:], other[:])
}

// Subtract removes all the capabilities of another set from this set.
func (s *Set) Subtract(other *Set) {
	utils.BitsetSubtract(s[:], other[:])
}

// Empty returns whether the set is empty.
func (s *Set) Empty() bool {
	return utils.BitsetEmpty(s[:])
}

const defaultMaxPayloadLength = 450

// Strings returns all of our enabled capabilities as a slice of strings.
func (s *Set) Strings(version Version, values Values, maxLen int) (result []string) {
	if maxLen == 0 {
		maxLen = defaultMaxPayloadLength
	}
	var t utils.TokenLineBuilder
	t.Initialize(maxLen, " ")

	var capab Capability
	asSlice := s[:]
	for capab = 0; capab < numCapabs; capab++ {
		// XXX clients that only support CAP LS 301 cannot handle multiline
		// responses. omit some CAPs in this case, forcing the response to fit on
		// a single line. this is technically buggy for CAP LIST (as opposed to LS)
		// but it shouldn't matter
		if version < Cap302 && !isAllowed301(capab) {
			continue
		}
		// skip any capabilities that are not enabled
		if !utils.BitsetGet(asSlice, uint(capab)) {
			continue
		}
		capString := capab.Name()
		if version >= Cap302 {
			val, exists := values[capab]
			if exists {
				capString = fmt.Sprintf("%s=%s", capString, val)
			}
		}
		t.Add(capString)
	}

	result = t.Lines()
	if result == nil {
		result = []string{""}
	}
	return
}

// this is a fixed whitelist of caps that are eligible for display in CAP LS 301
func isAllowed301(capab Capability) bool {
	switch capab {
	case AccountNotify, AccountTag, AwayNotify, Batch, ChgHost, Chathistory, EventPlayback,
		Relaymsg, EchoMessage, Nope, ExtendedJoin, InviteNotify, LabeledResponse, MessageTags,
		MultiPrefix, SASL, ServerTime, SetName, STS, UserhostInNames, ZNCSelfMessage, ZNCPlayback:
		return true
	default:
		return false
	}
}
