package utils

// Copyright (c) 2014 Kevin Wallace <kevin@pentabarf.net>
// Found here: https://github.com/kevinwallace/fieldsn
// Released under the MIT license
// XXX this implementation treats negative n as "return nil",
// unlike stdlib SplitN and friends, which treat it as "no limit"

// Original source code below:

// Package fieldsn implements FieldsN and FieldsFuncN,
// which are conspicuously missing from the strings package.

import (
	"unicode"
)

// FieldsN is like strings.Fields, but returns at most n fields,
// and the nth field includes any whitespace at the end of the string.
func FieldsN(s string, n int) []string {
	return FieldsFuncN(s, unicode.IsSpace, n)
}

// FieldsFuncN is like strings.FieldsFunc, but returns at most n fields,
// and the nth field includes any runes at the end of the string normally excluded by f.
func FieldsFuncN(s string, f func(rune) bool, n int) []string {
	if n <= 0 {
		return nil
	}

	a := make([]string, 0, n)
	na := 0
	fieldStart := -1
	for i, rune := range s {
		if f(rune) {
			if fieldStart >= 0 {
				a = append(a, s[fieldStart:i])
				na++
				fieldStart = -1
			}
		} else if fieldStart == -1 {
			fieldStart = i
			if na+1 == n {
				break
			}
		}
	}
	if fieldStart >= 0 {
		a = append(a, s[fieldStart:])
	}
	return a
}
