// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package caps

import "testing"
import "reflect"

func TestSets(t *testing.T) {
	s1 := NewSet()

	s1.Enable(AccountTag, EchoMessage, UserhostInNames)

	if !s1.Has(AccountTag, EchoMessage, UserhostInNames) {
		t.Error("Did not have the tags we expected")
	}

	if s1.Has(AccountTag, EchoMessage, STS, UserhostInNames) {
		t.Error("Has() returned true when we don't have all the given capabilities")
	}

	s1.Disable(AccountTag)

	if s1.Has(AccountTag) {
		t.Error("Disable() did not correctly disable the given capability")
	}

	enabledCaps := make(map[Capability]bool)
	for _, capab := range s1.List() {
		enabledCaps[capab] = true
	}
	expectedCaps := map[Capability]bool{
		EchoMessage:     true,
		UserhostInNames: true,
	}
	if !reflect.DeepEqual(enabledCaps, expectedCaps) {
		t.Errorf("Enabled and expected capability lists do not match: %v, %v", enabledCaps, expectedCaps)
	}

	// make sure re-enabling doesn't add to the count or something weird like that
	s1.Enable(EchoMessage)

	if s1.Count() != 2 {
		t.Error("Count() did not match expected capability count")
	}
}
