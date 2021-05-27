//go:generate go run maketables.go > tables.go

package confusables

import (
	"bytes"

	"golang.org/x/text/unicode/norm"
)

// TODO: document casefolding approaches
// (suggest to force casefold strings; explain how to catch paypal - pAypal)
// TODO: DOC you might want to store the Skeleton and check against it later
// TODO: implement xidmodifications.txt restricted characters

type lookupFunc func(rune) (string)

func lookupReplacement(r rune) string {
	return confusablesMap[r]
}

func lookupReplacementTweaked(r rune) string {
	if replacement, ok := tweaksMap[r]; ok {
		return replacement
	}
	return confusablesMap[r]
}

func skeletonBase(s string, lookup lookupFunc) string {

	// 1. Converting X to NFD format
	s = norm.NFD.String(s)

	// 2. Successively mapping each source character in X to the target string
	// according to the specified data table
	var buf bytes.Buffer
	changed := false // fast path: if this remains false, keep s intact
	prevPos := 0
	var replacement string
	for i, r := range s {
		if changed && replacement == "" {
			buf.WriteString(s[prevPos:i])
		}
		prevPos = i
		replacement = lookup(r)
		if replacement != "" {
			if !changed {
				changed = true
				// first replacement: copy over the previously unmodified text
				buf.WriteString(s[:i])
			}
			buf.WriteString(replacement)
		}
	}
	if changed && replacement == "" {
		buf.WriteString(s[prevPos:]) // loop-and-a-half
	}
	if changed {
		s = buf.String()
	}

	// 3. Reapplying NFD
	s = norm.NFD.String(s)

	return s
}

// Skeleton converts a string to its "skeleton" form
// as described in http://www.unicode.org/reports/tr39/#Confusable_Detection
func Skeleton(s string) string {
	return skeletonBase(s, lookupReplacement)
}

// SkeletonTweaked is like Skeleton, but it implements some custom overrides
// to the confusables table (currently it removes the m -> rn mapping):
func SkeletonTweaked(s string) string {
	return skeletonBase(s, lookupReplacementTweaked)
}

func Confusable(x, y string) bool {
	return Skeleton(x) == Skeleton(y)
}
