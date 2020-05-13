// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import (
	"regexp"
	"testing"
)

func globMustCompile(glob string) *regexp.Regexp {
	re, err := CompileGlob(glob, false)
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

func BenchmarkGlob(b *testing.B) {
	g := globMustCompile("https://*google.com")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.MatchString("https://www.google.com")
	}
}

func BenchmarkGlobCompilation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CompileGlob("https://*google.com", false)
	}
}

// these are actual bans from my production network :-/
var bans = []string{
	"*!*@tor-network.onion",
	"`!*@*",
	"qanon!*@*",
	"*!bibi@tor-network.onion",
	"shivarm!*@*",
	"8====d!*@*",
	"shiviram!*@*",
	"poop*!*@*",
	"shivoram!*@*",
	"shivvy!*@*",
	"shavirim!*@*",
	"shivarm_!*@*",
	"_!*@*",
}

func TestMasks(t *testing.T) {
	matcher, err := CompileMasks(bans)
	if err != nil {
		panic(err)
	}

	if !matcher.MatchString("evan!user@tor-network.onion") {
		t.Errorf("match expected")
	}
	if !matcher.MatchString("`!evan@b9un4fv3he44q.example.com") {
		t.Errorf("match expected")
	}
	if matcher.MatchString("horse!horse@t5dwi8vacg47y.example.com") {
		t.Errorf("match not expected")
	}
	if matcher.MatchString("horse_!horse@t5dwi8vacg47y.example.com") {
		t.Errorf("match not expected")
	}
	if matcher.MatchString("shivaram!shivaram@yrqgsrjy2p7my.example.com") {
		t.Errorf("match not expected")
	}
}

func BenchmarkMasksCompile(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CompileMasks(bans)
	}
}

func BenchmarkMasksMatch(b *testing.B) {
	matcher, _ := CompileMasks(bans)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.MatchString("evan!user@tor-network.onion")
		matcher.MatchString("horse_!horse@t5dwi8vacg47y.example.com")
		matcher.MatchString("shivaram!shivaram@yrqgsrjy2p7my.example.com")
	}
}

// compare performance to compilation of the | clauses as separate regexes
// first for compilation, then for matching

func compileAll(masks []string) (result []*regexp.Regexp, err error) {
	a := make([]*regexp.Regexp, 0, len(masks))
	for _, mask := range masks {
		m, err := CompileGlob(mask, false)
		if err != nil {
			return nil, err
		}
		a = append(a, m)
	}
	return a, nil
}

func matchesAny(masks []*regexp.Regexp, str string) bool {
	for _, r := range masks {
		if r.MatchString(str) {
			return true
		}
	}
	return false
}

func BenchmarkLinearCompile(b *testing.B) {
	for i := 0; i < b.N; i++ {
		compileAll(bans)
	}
}

func BenchmarkLinearMatch(b *testing.B) {
	a, err := compileAll(bans)
	if err != nil {
		panic(err)
	}
	if matchesAny(a, "horse_!horse@t5dwi8vacg47y.example.com") {
		panic("incorrect match")
	}
	if !matchesAny(a, "evan!user@tor-network.onion") {
		panic("incorrect match")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matchesAny(a, "horse_!horse@t5dwi8vacg47y.example.com")
		matchesAny(a, "evan!user@tor-network.onion")
		matchesAny(a, "shivaram!shivaram@yrqgsrjy2p7my.example.com")
	}
}
