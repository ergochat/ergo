// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"strings"

	"github.com/oragono/confusables"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/secure/precis"
	"golang.org/x/text/width"
)

const (
	casemappingName = "rfc8265"
)

// Each pass of PRECIS casefolding is a composition of idempotent operations,
// but not idempotent itself. Therefore, the spec says "do it four times and hope
// it converges" (lolwtf). Golang's PRECIS implementation has a "repeat" option,
// which provides this functionality, but unfortunately it's not exposed publicly.
func iterateFolding(profile *precis.Profile, oldStr string) (str string, err error) {
	str = oldStr
	// follow the stabilizing rules laid out here:
	// https://tools.ietf.org/html/draft-ietf-precis-7564bis-10.html#section-7
	for i := 0; i < 4; i++ {
		str, err = profile.CompareKey(str)
		if err != nil {
			return "", err
		}
		if oldStr == str {
			break
		}
		oldStr = str
	}
	if oldStr != str {
		return "", errCouldNotStabilize
	}
	return str, nil
}

// Casefold returns a casefolded string, without doing any name or channel character checks.
func Casefold(str string) (string, error) {
	return iterateFolding(precis.UsernameCaseMapped, str)
}

// CasefoldChannel returns a casefolded version of a channel name.
func CasefoldChannel(name string) (string, error) {
	if len(name) == 0 {
		return "", errStringIsEmpty
	}

	// don't casefold the preceding #'s
	var start int
	for start = 0; start < len(name) && name[start] == '#'; start += 1 {
	}

	if start == 0 {
		// no preceding #'s
		return "", errInvalidCharacter
	}

	lowered, err := Casefold(name[start:])
	if err != nil {
		return "", err
	}

	// space can't be used
	// , is used as a separator
	// * is used in mask matching
	// ? is used in mask matching
	if strings.ContainsAny(lowered, " ,*?") {
		return "", errInvalidCharacter
	}

	return name[:start] + lowered, err
}

// CasefoldName returns a casefolded version of a nick/user name.
func CasefoldName(name string) (string, error) {
	lowered, err := Casefold(name)

	if err != nil {
		return "", err
	} else if len(lowered) == 0 {
		return "", errStringIsEmpty
	}

	// space can't be used
	// , is used as a separator
	// * is used in mask matching
	// ? is used in mask matching
	// . denotes a server name
	// ! separates nickname from username
	// @ separates username from hostname
	// : means trailing
	// # is a channel prefix
	// ~&@%+ are channel membership prefixes
	// - I feel like disallowing
	if strings.ContainsAny(lowered, " ,*?.!@:") || strings.ContainsAny(string(lowered[0]), "#~&@%+-") {
		return "", errInvalidCharacter
	}

	return lowered, err
}

// returns true if the given name is a valid ident, using a mix of Insp and
// Chary's ident restrictions.
func isIdent(name string) bool {
	if len(name) < 1 {
		return false
	}

	for i := 0; i < len(name); i++ {
		chr := name[i]
		if (chr >= 'a' && chr <= 'z') || (chr >= 'A' && chr <= 'Z') || (chr >= '0' && chr <= '9') {
			continue // alphanumerics
		}
		if i == 0 {
			return false // first char must be alnum
		}
		switch chr {
		case '[', '\\', ']', '^', '_', '{', '|', '}', '-', '.', '`':
			continue // allowed chars
		default:
			return false // disallowed chars
		}
	}

	return true
}

// Skeleton produces a canonicalized identifier that tries to catch
// homoglyphic / confusable identifiers. It's a tweaked version of the TR39
// skeleton algorithm. We apply the skeleton algorithm first and only then casefold,
// because casefolding first would lose some information about visual confusability.
// This has the weird consequence that the skeleton is not a function of the
// casefolded identifier --- therefore it must always be computed
// from the original (unfolded) identifier and stored/tracked separately from the
// casefolded identifier.
func Skeleton(name string) (string, error) {
	// XXX the confusables table includes some, but not all, fullwidth->standard
	// mappings for latin characters. do a pass of explicit width folding,
	// same as PRECIS:
	name = width.Fold.String(name)

	name = confusables.SkeletonTweaked(name)

	// internationalized lowercasing for skeletons; this is much more lenient than
	// Casefold. In particular, skeletons are expected to mix scripts (which may
	// violate the bidi rule). We also don't care if they contain runes
	// that are disallowed by PRECIS, because every identifier must independently
	// pass PRECIS --- we are just further canonicalizing the skeleton.
	return cases.Lower(language.Und).String(name), nil
}
