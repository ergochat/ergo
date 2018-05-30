// Copyright (c) 2018 Shivaram Lingamneni
// released under the MIT license

package modes

import (
	"reflect"
	"testing"
)

func TestParseChannelModeChanges(t *testing.T) {
	modes, unknown := ParseChannelModeChanges("+h", "wrmsr")
	if len(unknown) > 0 {
		t.Errorf("unexpected unknown mode change: %v", unknown)
	}
	expected := ModeChange{
		Op:   Add,
		Mode: Halfop,
		Arg:  "wrmsr",
	}
	if len(modes) != 1 || modes[0] != expected {
		t.Errorf("unexpected mode change: %v", modes)
	}

	modes, unknown = ParseChannelModeChanges("-v", "shivaram")
	if len(unknown) > 0 {
		t.Errorf("unexpected unknown mode change: %v", unknown)
	}
	expected = ModeChange{
		Op:   Remove,
		Mode: Voice,
		Arg:  "shivaram",
	}
	if len(modes) != 1 || modes[0] != expected {
		t.Errorf("unexpected mode change: %v", modes)
	}

	modes, unknown = ParseChannelModeChanges("+tx")
	if len(unknown) != 1 || !unknown['x'] {
		t.Errorf("expected that x is an unknown mode, instead: %v", unknown)
	}
	expected = ModeChange{
		Op:   Add,
		Mode: OpOnlyTopic,
		Arg:  "",
	}
	if len(modes) != 1 || modes[0] != expected {
		t.Errorf("unexpected mode change: %v", modes)
	}
}

func TestSetMode(t *testing.T) {
	set := NewModeSet()

	if applied := set.SetMode(Invisible, false); applied != false {
		t.Errorf("all modes should be false by default")
	}

	if applied := set.SetMode(Invisible, true); applied != true {
		t.Errorf("initial SetMode call should return true")
	}

	set.SetMode(Operator, true)

	if applied := set.SetMode(Invisible, true); applied != false {
		t.Errorf("redundant SetMode call should return false")
	}

	expected1 := []Mode{Invisible, Operator}
	expected2 := []Mode{Operator, Invisible}
	if allModes := set.AllModes(); !(reflect.DeepEqual(allModes, expected1) || reflect.DeepEqual(allModes, expected2)) {
		t.Errorf("unexpected AllModes value: %v", allModes)
	}

	if modeString := set.String(); !(modeString == "io" || modeString == "oi") {
		t.Errorf("unexpected modestring: %s", modeString)
	}
}

func TestNilReceivers(t *testing.T) {
	var set ModeSet

	if set.HasMode(Invisible) {
		t.Errorf("nil ModeSet should not have any modes")
	}

	str := set.String()
	if str != "" {
		t.Errorf("nil Modeset should have empty String(), got %v instead", str)
	}
}
