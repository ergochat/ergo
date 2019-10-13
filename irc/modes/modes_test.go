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

	modes, unknown = ParseChannelModeChanges("+b")
	if len(unknown) > 0 {
		t.Errorf("unexpected unknown mode change: %v", unknown)
	}
	// +b with no argument becomes a list operation
	expectedChanges := ModeChanges{{
		Op:   List,
		Mode: BanMask,
	}}
	if !reflect.DeepEqual(modes, expectedChanges) {
		t.Errorf("unexpected mode change: %v instead of %v", modes, expectedChanges)
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

func TestModeString(t *testing.T) {
	set := NewModeSet()
	set.SetMode('A', true)
	set.SetMode('z', true)

	if modeString := set.String(); !(modeString == "Az" || modeString == "Za") {
		t.Errorf("unexpected modestring: %s", modeString)
	}
}

func TestNilReceivers(t *testing.T) {
	set := NewModeSet()
	set = nil

	if set.HasMode(Invisible) {
		t.Errorf("nil ModeSet should not have any modes")
	}

	str := set.String()
	if str != "" {
		t.Errorf("nil Modeset should have empty String(), got %v instead", str)
	}
}

func TestHighestChannelUserMode(t *testing.T) {
	set := NewModeSet()

	if set.HighestChannelUserMode() != Mode(0) {
		t.Errorf("no channel user modes should be present yet")
	}

	set.SetMode(Voice, true)
	if set.HighestChannelUserMode() != Voice {
		t.Errorf("should see that user is voiced")
	}

	set.SetMode(ChannelAdmin, true)
	if set.HighestChannelUserMode() != ChannelAdmin {
		t.Errorf("should see that user has channel admin")
	}

	set = nil
	if set.HighestChannelUserMode() != Mode(0) {
		t.Errorf("nil modeset should have the zero mode as highest channel-user mode")
	}
}

func BenchmarkModeString(b *testing.B) {
	set := NewModeSet()
	set.SetMode('A', true)
	set.SetMode('N', true)
	set.SetMode('b', true)
	set.SetMode('i', true)
	set.SetMode('x', true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = set.String()
	}
}
