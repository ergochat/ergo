// Copyright (c) 2017 Euan Kemp
// Copyright (c) 2017 Daniel Oaks
// released under the MIT license

package irc

import (
	"fmt"
	"testing"

	"github.com/ergochat/ergo/irc/i18n"
)

func TestCasefoldChannelAllCasemappings(t *testing.T) {
	oldGlobalCasemapping := globalCasemappingSetting
	t.Cleanup(func() {
		globalCasemappingSetting = oldGlobalCasemapping
	})

	globalCasemappingSetting = i18n.CasemappingPRECIS

	type channelTest struct {
		channel  string
		folded   string
		nonASCII bool
		err      bool
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
			channel:  "#中文频道",
			folded:   "#中文频道",
			nonASCII: true,
		},
		{
			// Hebrew; it's up to the client to display this right-to-left, including the #
			channel:  "#שלום",
			folded:   "#שלום",
			nonASCII: true,
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

	// don't test permissive because it doesn't fail on bidi violations
	casemappings := []i18n.Casemapping{i18n.CasemappingASCII, i18n.CasemappingPRECIS}

	for _, casemapping := range casemappings {
		globalCasemappingSetting = casemapping

		for i, tt := range testCases {
			t.Run(fmt.Sprintf("case %d: %s", i, tt.channel), func(t *testing.T) {
				res, err := CasefoldChannel(tt.channel)
				errExpected := tt.err || (tt.nonASCII && (casemapping == i18n.CasemappingASCII || casemapping == i18n.CasemappingRFC1459Strict))
				if errExpected && err == nil {
					t.Errorf("expected error when casefolding [%s] under casemapping %d, but did not receive one", tt.channel, casemapping)
					return
				}
				if !errExpected && err != nil {
					t.Errorf("unexpected error while casefolding [%s] under casemapping %d: %s", tt.channel, casemapping, err.Error())
					return
				}
				if !errExpected && tt.folded != res {
					t.Errorf("expected [%v] to be [%v] under casemapping %d", res, tt.folded, casemapping)
				}
			})
		}
	}
}

func TestCasefoldNameAllCasemappings(t *testing.T) {
	oldGlobalCasemapping := globalCasemappingSetting
	t.Cleanup(func() {
		globalCasemappingSetting = oldGlobalCasemapping
	})

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
		"~o", "&o", "@o", "%h", "+v", "-m", "\t", "a\tb",
	} {
		testCases = append(testCases, nameTest{name: errCase, err: true})
	}

	casemappings := []i18n.Casemapping{i18n.CasemappingASCII, i18n.CasemappingPRECIS, i18n.CasemappingPermissive, i18n.CasemappingRFC1459Strict}

	for _, casemapping := range casemappings {
		globalCasemappingSetting = casemapping

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

func TestCanonicalizeMaskWildcard(t *testing.T) {
	tester := func(input, expected string, expectedErr error) {
		out, err := CanonicalizeMaskWildcard(input)
		if expectedErr == nil && out != expected {
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
	tester("*SHIVARAM*   ", "*shivaram*!*@*", nil)

	tester(":shivaram", "", errInvalidCharacter)
	tester("shivaram!us er@host", "", errInvalidCharacter)
	tester("shivaram!user@ho st", "", errInvalidCharacter)
}
