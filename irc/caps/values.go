// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package caps

import "sync"

// Values holds capability values.
type Values struct {
	sync.RWMutex
	// values holds our actual capability values.
	values map[Capability]string
}

// NewValues returns a new Values.
func NewValues() *Values {
	return &Values{
		values: make(map[Capability]string),
	}
}

// Set sets the value for the given capability.
func (v *Values) Set(capab Capability, value string) {
	v.Lock()
	defer v.Unlock()

	v.values[capab] = value
}

// Unset removes the value for the given capability, if it exists.
func (v *Values) Unset(capab Capability) {
	v.Lock()
	defer v.Unlock()

	delete(v.values, capab)
}

// Get returns the value of the given capability, and whether one exists.
func (v *Values) Get(capab Capability) (string, bool) {
	v.RLock()
	defer v.RUnlock()

	value, exists := v.values[capab]
	return value, exists
}
