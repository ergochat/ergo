// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package caps

import (
	"sort"
	"strings"

	"github.com/oragono/oragono/irc/utils"
)

// Set holds a set of enabled capabilities.
type Set [bitsetLen]uint64

// NewSet returns a new Set, with the given capabilities enabled.
func NewSet(capabs ...Capability) *Set {
	var newSet Set
	newSet.Enable(capabs...)
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

// String returns all of our enabled capabilities as a string.
func (s *Set) String(version Version, values *Values) string {
	var strs sort.StringSlice

	var capab Capability
	asSlice := s[:]
	for capab = 0; capab < numCapabs; capab++ {
		// skip any capabilities that are not enabled
		if !utils.BitsetGet(asSlice, uint(capab)) {
			continue
		}
		capString := capab.Name()
		if version == Cap302 {
			val, exists := values.Get(capab)
			if exists {
				capString += "=" + val
			}
		}
		strs = append(strs, capString)
	}

	// sort the cap string before we send it out
	sort.Sort(strs)

	return strings.Join(strs, " ")
}
