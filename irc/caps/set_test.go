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

	// make sure add and remove work fine
	s1.Add(InviteNotify)
	s1.Remove(EchoMessage)

	if s1.Count() != 2 {
		t.Error("Count() did not match expected capability count")
	}

	// test String()
	values := NewValues()
	values.Set(InviteNotify, "invitemepls")

	actualCap301ValuesString := s1.String(Cap301, values)
	expectedCap301ValuesString := "invite-notify userhost-in-names"
	if actualCap301ValuesString != expectedCap301ValuesString {
		t.Errorf("Generated Cap301 values string [%s] did not match expected values string [%s]", actualCap301ValuesString, expectedCap301ValuesString)
	}

	actualCap302ValuesString := s1.String(Cap302, values)
	expectedCap302ValuesString := "invite-notify=invitemepls userhost-in-names"
	if actualCap302ValuesString != expectedCap302ValuesString {
		t.Errorf("Generated Cap302 values string [%s] did not match expected values string [%s]", actualCap302ValuesString, expectedCap302ValuesString)
	}
}

func BenchmarkSetReads(b *testing.B) {
	set := NewSet(UserhostInNames, EchoMessage)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.Has(UserhostInNames)
		set.Has(LabeledResponse)
		set.Has(EchoMessage)
		set.Has(Rename)
	}
}

func BenchmarkSetWrites(b *testing.B) {
	for i := 0; i < b.N; i++ {
		set := NewSet(UserhostInNames, EchoMessage)
		set.Add(Rename)
		set.Add(ExtendedJoin)
		set.Remove(UserhostInNames)
		set.Remove(LabeledResponse)
	}
}
