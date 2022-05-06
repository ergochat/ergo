// Copyright (c) 2017 Daniel Oaks
// released under the MIT license

package irc

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/ergochat/ergo/irc/modes"
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

func TestParseDefaultUserModes(t *testing.T) {
	iR := "+iR"
	i := "+i"
	empty := ""
	rminusi := "+R -i"

	var parseTests = []struct {
		raw      *string
		expected modes.Modes
	}{
		{&iR, modes.Modes{modes.Invisible, modes.RegisteredOnly}},
		{&i, modes.Modes{modes.Invisible}},
		{&empty, modes.Modes{}},
		{&rminusi, modes.Modes{modes.RegisteredOnly}},
		{nil, modes.Modes{}},
	}

	for _, testcase := range parseTests {
		result := ParseDefaultUserModes(testcase.raw)
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

func assertEqual(found, expected interface{}) {
	if !reflect.DeepEqual(found, expected) {
		panic(fmt.Sprintf("found %#v, expected %#v", found, expected))
	}
}

func TestChannelUserModeHasPrivsOver(t *testing.T) {
	assertEqual(channelUserModeHasPrivsOver(modes.Voice, modes.Halfop), false)
	assertEqual(channelUserModeHasPrivsOver(modes.Mode(0), modes.Halfop), false)
	assertEqual(channelUserModeHasPrivsOver(modes.Voice, modes.Mode(0)), false)
	assertEqual(channelUserModeHasPrivsOver(modes.ChannelAdmin, modes.ChannelAdmin), false)
	assertEqual(channelUserModeHasPrivsOver(modes.Halfop, modes.Halfop), false)
	assertEqual(channelUserModeHasPrivsOver(modes.Voice, modes.Voice), false)

	assertEqual(channelUserModeHasPrivsOver(modes.Halfop, modes.Voice), true)
	assertEqual(channelUserModeHasPrivsOver(modes.ChannelFounder, modes.ChannelAdmin), true)
	assertEqual(channelUserModeHasPrivsOver(modes.ChannelOperator, modes.ChannelOperator), true)
}
