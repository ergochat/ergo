// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import (
	"regexp"
	"testing"
)

func globMustCompile(glob string) *regexp.Regexp {
	re, err := CompileGlob(glob)
	if err != nil {
		panic(err)
	}
	return re
}

func assertMatches(glob, str string, match bool, t *testing.T) {
	re := globMustCompile(glob)
	if re.MatchString(str) != match {
		t.Errorf("should %s match %s? %t, but got %t instead", glob, str, match, !match)
	}
}

func TestGlob(t *testing.T) {
	assertMatches("https://testnet.oragono.io", "https://testnet.oragono.io", true, t)
	assertMatches("https://*.oragono.io", "https://testnet.oragono.io", true, t)
	assertMatches("*://*.oragono.io", "https://testnet.oragono.io", true, t)
	assertMatches("*://*.oragono.io", "https://oragono.io", false, t)
	assertMatches("*://*.oragono.io", "https://githubusercontent.com", false, t)
	assertMatches("*://*.oragono.io", "https://testnet.oragono.io.example.com", false, t)

	assertMatches("", "", true, t)
	assertMatches("", "x", false, t)
	assertMatches("*", "", true, t)
	assertMatches("*", "x", true, t)

	assertMatches("c?b", "cab", true, t)
	assertMatches("c?b", "cub", true, t)
	assertMatches("c?b", "cb", false, t)
	assertMatches("c?b", "cube", false, t)
	assertMatches("?*", "cube", true, t)
	assertMatches("?*", "", false, t)

	assertMatches("S*e", "Skåne", true, t)
	assertMatches("Sk?ne", "Skåne", true, t)
}
