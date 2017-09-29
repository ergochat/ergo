// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package caps

import (
	"sort"
	"strings"
	"sync"
)

// Set holds a set of enabled capabilities.
type Set struct {
	sync.RWMutex
	// capabilities holds the capabilities this manager has.
	capabilities map[Capability]bool
}

// NewSet returns a new Set, with the given capabilities enabled.
func NewSet(capabs ...Capability) *Set {
	newSet := Set{
		capabilities: make(map[Capability]bool),
	}
	newSet.Enable(capabs...)

	return &newSet
}

// Enable enables the given capabilities.
func (s *Set) Enable(capabs ...Capability) {
	s.Lock()
	defer s.Unlock()

	for _, capab := range capabs {
		s.capabilities[capab] = true
	}
}

// Disable disables the given capabilities.
func (s *Set) Disable(capabs ...Capability) {
	s.Lock()
	defer s.Unlock()

	for _, capab := range capabs {
		delete(s.capabilities, capab)
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

// Has returns true if this set has the given capabilities.
func (s *Set) Has(caps ...Capability) bool {
	s.RLock()
	defer s.RUnlock()

	for _, cap := range caps {
		if !s.capabilities[cap] {
			return false
		}
	}
	return true
}

// List return a list of our enabled capabilities.
func (s *Set) List() []Capability {
	s.RLock()
	defer s.RUnlock()

	var allCaps []Capability
	for capab := range s.capabilities {
		allCaps = append(allCaps, capab)
	}

	return allCaps
}

// Count returns how many enabled caps this set has.
func (s *Set) Count() int {
	s.RLock()
	defer s.RUnlock()

	return len(s.capabilities)
}

// String returns all of our enabled capabilities as a string.
func (s *Set) String(version Version, values *Values) string {
	s.RLock()
	defer s.RUnlock()

	var strs sort.StringSlice

	for capability := range s.capabilities {
		capString := capability.Name()
		if version == Cap302 {
			val, exists := values.Get(capability)
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
