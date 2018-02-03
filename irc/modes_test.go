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

	var config Config
	for _, testcase := range parseTests {
		config.Channels.DefaultModes = testcase.raw
		result := ParseDefaultChannelModes(&config)
		if !reflect.DeepEqual(result, testcase.expected) {
			t.Errorf("expected modes %s, got %s", testcase.expected, result)
		}
	}
}
