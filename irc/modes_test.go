// Copyright (c) 2017 Daniel Oaks
// released under the MIT license

package irc

import (
	"reflect"
	"testing"

	"github.com/oragono/oragono/irc/modes"
)

func TestParseDefaultChannelModes(t *testing.T) {
	nt := "+nt"
	n := "+n"
	empty := ""
	tminusi := "+t -i"

	var parseTests = []struct {
		raw      *string
		expected modes.Modes
	}{
		{&nt, modes.Modes{modes.NoOutside, modes.OpOnlyTopic}},
		{&n, modes.Modes{modes.NoOutside}},
		{&empty, modes.Modes{}},
		{&tminusi, modes.Modes{modes.OpOnlyTopic}},
		{nil, modes.Modes{modes.NoOutside, modes.OpOnlyTopic}},
	}

	for _, testcase := range parseTests {
		result := ParseDefaultChannelModes(testcase.raw)
		if !reflect.DeepEqual(result, testcase.expected) {
			t.Errorf("expected modes %s, got %s", testcase.expected, result)
		}
	}
}

func TestUmodeGreaterThan(t *testing.T) {
	if !umodeGreaterThan(modes.Halfop, modes.Voice) {
		t.Errorf("expected Halfop > Voice")
	}

	if !umodeGreaterThan(modes.Voice, modes.Mode(0)) {
		t.Errorf("expected Voice > 0 (the zero value of modes.Mode)")
	}

	if umodeGreaterThan(modes.ChannelAdmin, modes.ChannelAdmin) {
		t.Errorf("modes should not be greater than themselves")
	}
}
