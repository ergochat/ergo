// Copyright (c) 2017 Daniel Oaks
// released under the MIT license

package irc

import (
	"reflect"
	"testing"
)

func TestParseDefaultChannelModes(t *testing.T) {
	nt := "+nt"
	n := "+n"
	empty := ""
	tminusi := "+t -i"

	var parseTests = []struct {
		raw      *string
		expected Modes
	}{
		{&nt, Modes{NoOutside, OpOnlyTopic}},
		{&n, Modes{NoOutside}},
		{&empty, Modes{}},
		{&tminusi, Modes{OpOnlyTopic}},
		{nil, Modes{NoOutside, OpOnlyTopic}},
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
