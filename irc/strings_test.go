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
		{
			channel: "##",
			folded:  "##",
		},
		{
			channel: "##Ubuntu",
			folded:  "##ubuntu",
		},
		{
			channel: "#中文频道",
			folded:  "#中文频道",
		},
		{
			// Hebrew; it's up to the client to display this right-to-left, including the #
			channel: "#שלום",
			folded:  "#שלום",
		},
	}

	for _, errCase := range []string{
		"", "#*starpower", "# NASA", "#interro?", "OOF#", "foo",
		// bidi violation mixing latin and hebrew characters:
		"#shalomעליכם",
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

func TestIsIdent(t *testing.T) {
	assertIdent := func(str string, expected bool) {
		if isIdent(str) != expected {
			t.Errorf("expected [%s] to have identness [%t], but got [%t]", str, expected, !expected)
		}
	}

	assertIdent("warning", true)
	assertIdent("sid3225", true)
	assertIdent("dan.oak25", true)
	assertIdent("dan.oak[25]", true)
	assertIdent("phi@#$%ip", false)
	assertIdent("Νικηφόρος", false)
	assertIdent("-dan56", false)
}

func TestSkeleton(t *testing.T) {
	skeleton := func(str string) string {
		skel, err := Skeleton(str)
		if err != nil {
			t.Error(err)
		}
		return skel
	}

	if skeleton("warning") == skeleton("waming") {
		t.Errorf("Oragono shouldn't consider rn confusable with m")
	}

	if skeleton("Phi|ip") != "philip" {
		t.Errorf("but we still consider pipe confusable with l")
	}

	if skeleton("ｓｍｔ") != skeleton("smt") {
		t.Errorf("fullwidth characters should skeletonize to plain old ascii characters")
	}

	if skeleton("ＳＭＴ") != skeleton("smt") {
		t.Errorf("after skeletonizing, we should casefold")
	}

	if skeleton("smｔ") != skeleton("smt") {
		t.Errorf("our friend lover successfully tricked the skeleton algorithm!")
	}

	if skeleton("еvan") != "evan" {
		t.Errorf("we must protect against cyrillic homoglyph attacks")
	}

	if skeleton("еmily") != skeleton("emily") {
		t.Errorf("we must protect against cyrillic homoglyph attacks")
	}

	if skeleton("РОТАТО") != "potato" {
		t.Errorf("we must protect against cyrillic homoglyph attacks")
	}

	// should not raise an error:
	skeleton("けらんぐ")
}
