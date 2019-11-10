// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package caps

import "testing"
import "reflect"

func TestSets(t *testing.T) {
	s1 := NewSet()

	s1.Enable(AccountTag, EchoMessage, UserhostInNames)

	if !(s1.Has(AccountTag) && s1.Has(EchoMessage) && s1.Has(UserhostInNames)) {
		t.Error("Did not have the tags we expected")
	}

	if s1.Has(STS) {
		t.Error("Has() returned true when we don't have the given capability")
	}

	s1.Disable(AccountTag)

	if s1.Has(AccountTag) {
		t.Error("Disable() did not correctly disable the given capability")
	}

	enabledCaps := NewSet()
	enabledCaps.Union(s1)
	expectedCaps := NewSet(EchoMessage, UserhostInNames)
	if !reflect.DeepEqual(enabledCaps, expectedCaps) {
		t.Errorf("Enabled and expected capability lists do not match: %v, %v", enabledCaps, expectedCaps)
	}

	// make sure re-enabling doesn't add to the count or something weird like that
	s1.Enable(EchoMessage)

	// make sure add and remove work fine
	s1.Add(InviteNotify)
	s1.Remove(EchoMessage)

	if !s1.Has(InviteNotify) || s1.Has(EchoMessage) {
		t.Error("Add/Remove don't work")
	}

	// test Strings()
	values := make(Values)
	values[InviteNotify] = "invitemepls"

	actualCap301ValuesString := s1.Strings(Cap301, values, 0)
	expectedCap301ValuesString := []string{"invite-notify userhost-in-names"}
	if !reflect.DeepEqual(actualCap301ValuesString, expectedCap301ValuesString) {
		t.Errorf("Generated Cap301 values string [%v] did not match expected values string [%v]", actualCap301ValuesString, expectedCap301ValuesString)
	}

	actualCap302ValuesString := s1.Strings(Cap302, values, 0)
	expectedCap302ValuesString := []string{"invite-notify=invitemepls userhost-in-names"}
	if !reflect.DeepEqual(actualCap302ValuesString, expectedCap302ValuesString) {
		t.Errorf("Generated Cap302 values string [%s] did not match expected values string [%s]", actualCap302ValuesString, expectedCap302ValuesString)
	}
}

func TestSubtract(t *testing.T) {
	s1 := NewSet(AccountTag, EchoMessage, UserhostInNames, ServerTime)

	toRemove := NewSet(UserhostInNames, EchoMessage)
	s1.Subtract(toRemove)

	if !reflect.DeepEqual(s1, NewSet(AccountTag, ServerTime)) {
		t.Errorf("subtract doesn't work")
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
