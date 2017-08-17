// Copyright (c) 2017 Euan Kemp
// Copyright (c) 2017 Daniel Oaks
// released under the MIT license

package irc

import (
	"fmt"
	"testing"
)

func TestCasefoldChannel(t *testing.T) {
	type channelTest struct {
		channel string
		folded  string
		err     bool
	}
	testCases := []channelTest{
		{
			channel: "#foo",
			folded:  "#foo",
		},
		{
			channel: "#rfc1459[noncompliant]",
			folded:  "#rfc1459[noncompliant]",
		},
		{
			channel: "#{[]}",
			folded:  "#{[]}",
		},
		{
			channel: "#FOO",
			folded:  "#foo",
		},
		{
			channel: "#bang!",
			folded:  "#bang!",
		},
		{
			channel: "#",
			folded:  "#",
		},
	}

	for _, errCase := range []string{
		"", "#*starpower", "# NASA", "#interro?", "OOF#", "foo",
	} {
		testCases = append(testCases, channelTest{channel: errCase, err: true})
	}

	for i, tt := range testCases {
		t.Run(fmt.Sprintf("case %d: %s", i, tt.channel), func(t *testing.T) {
			res, err := CasefoldChannel(tt.channel)
			if tt.err && err == nil {
				t.Errorf("expected error when casefolding [%s], but did not receive one", tt.channel)
				return
			}
			if !tt.err && err != nil {
				t.Errorf("unexpected error while casefolding [%s]: %s", tt.channel, err.Error())
				return
			}
			if tt.folded != res {
				t.Errorf("expected [%v] to be [%v]", res, tt.folded)
			}
		})
	}
}

func TestCasefoldName(t *testing.T) {
	type nameTest struct {
		name   string
		folded string
		err    bool
	}
	testCases := []nameTest{
		{
			name:   "foo",
			folded: "foo",
		},
		{
			name:   "FOO",
			folded: "foo",
		},
	}

	for _, errCase := range []string{
		"", "#", "foo,bar", "star*man*junior", "lo7t?",
		"f.l", "excited!nick", "foo@bar", ":trail",
		"~o", "&o", "@o", "%h", "+v", "-m",
	} {
		testCases = append(testCases, nameTest{name: errCase, err: true})
	}

	for i, tt := range testCases {
		t.Run(fmt.Sprintf("case %d: %s", i, tt.name), func(t *testing.T) {
			res, err := CasefoldName(tt.name)
			if tt.err && err == nil {
				t.Errorf("expected error when casefolding [%s], but did not receive one", tt.name)
				return
			}
			if !tt.err && err != nil {
				t.Errorf("unexpected error while casefolding [%s]: %s", tt.name, err.Error())
				return
			}
			if tt.folded != res {
				t.Errorf("expected [%v] to be [%v]", res, tt.folded)
			}
		})
	}
}
