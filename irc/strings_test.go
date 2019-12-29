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
		"#tab\tcharacter", "#\t", "#carriage\rreturn",
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

func TestCanonicalizeMaskWildcard(t *testing.T) {
	tester := func(input, expected string, expectedErr error) {
		out, err := CanonicalizeMaskWildcard(input)
		if out != expected {
			t.Errorf("expected %s to canonicalize to %s, instead %s", input, expected, out)
		}
		if err != expectedErr {
			t.Errorf("expected %s to produce error %v, instead %v", input, expectedErr, err)
		}
	}

	tester("shivaram", "shivaram!*@*", nil)
	tester("slingamn!shivaram", "slingamn!shivaram@*", nil)
	tester("ברוך", "ברוך!*@*", nil)
	tester("hacker@monad.io", "*!hacker@monad.io", nil)
	tester("Evan!hacker@monad.io", "evan!hacker@monad.io", nil)
	tester("РОТАТО!Potato", "ротато!potato@*", nil)
	tester("tkadich*", "tkadich*!*@*", nil)
	tester("SLINGAMN!*@*", "slingamn!*@*", nil)
	tester("slingamn!shivaram*", "slingamn!shivaram*@*", nil)
	tester("slingamn!", "slingamn!*@*", nil)
	tester("shivaram*@good-fortune", "*!shivaram*@good-fortune", nil)
	tester("shivaram*", "shivaram*!*@*", nil)
	tester("Shivaram*", "shivaram*!*@*", nil)
	tester("*SHIVARAM*", "*shivaram*!*@*", nil)
}

func validFoldTester(first, second string, equal bool, folder func(string) (string, error), t *testing.T) {
	firstFolded, err := folder(first)
	if err != nil {
		panic(err)
	}
	secondFolded, err := folder(second)
	if err != nil {
		panic(err)
	}
	foundEqual := firstFolded == secondFolded
	if foundEqual != equal {
		t.Errorf("%s and %s: expected equality %t, but got %t", first, second, equal, foundEqual)
	}
}

func TestFoldPermissive(t *testing.T) {
	tester := func(first, second string, equal bool) {
		validFoldTester(first, second, equal, foldPermissive, t)
	}
	tester("SHIVARAM", "shivaram", true)
	tester("shIvaram", "shivaraM", true)
	tester("shivaram", "DAN-", false)
	tester("dolph🐬n", "DOLPH🐬n", true)
	tester("dolph🐬n", "dolph💻n", false)
	tester("9FRONT", "9front", true)
}

func TestFoldPermissiveInvalid(t *testing.T) {
	_, err := foldPermissive("a\tb")
	if err == nil {
		t.Errorf("whitespace should be invalid in identifiers")
	}
	_, err = foldPermissive("a\x00b")
	if err == nil {
		t.Errorf("the null byte should be invalid in identifiers")
	}
}

func TestFoldASCII(t *testing.T) {
	tester := func(first, second string, equal bool) {
		validFoldTester(first, second, equal, foldASCII, t)
	}
	tester("shivaram", "SHIVARAM", true)
	tester("X|Y", "x|y", true)
	tester("a != b", "A != B", true)
}

func TestFoldASCIIInvalid(t *testing.T) {
	_, err := foldASCII("\x01")
	if err == nil {
		t.Errorf("control characters should be invalid in identifiers")
	}
	_, err = foldASCII("\x7F")
	if err == nil {
		t.Errorf("control characters should be invalid in identifiers")
	}
}
