// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"strings"

	"github.com/oragono/confusables"
	"golang.org/x/text/secure/precis"
	"golang.org/x/text/unicode/norm"
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

// "boring" names are exempt from skeletonization.
// this is because confusables.txt considers various pure ASCII alphanumeric
// strings confusable: 0 and O, 1 and l, m and rn. IMO this causes more problems
// than it solves.
func isBoring(name string) bool {
	for i := 0; i < len(name); i += 1 {
		chr := name[i]
		if (chr >= 'a' && chr <= 'z') || (chr >= 'A' && chr <= 'Z') || (chr >= '0' && chr <= '9') {
			continue // alphanumerics
		}
		switch chr {
		case '$', '%', '^', '&', '(', ')', '{', '}', '[', ']', '<', '>', '=':
			continue // benign printable ascii characters
		default:
			return false // potentially confusable ascii like | ' `, non-ascii
		}
	}
	return true
}

var skeletonCasefolder = precis.NewIdentifier(precis.FoldWidth, precis.LowerCase(), precis.Norm(norm.NFC))

// similar to Casefold, but exempts the bidi rule, because skeletons may
// mix scripts strangely
func casefoldSkeleton(str string) (string, error) {
	return iterateFolding(skeletonCasefolder, str)
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
	if !isBoring(name) {
		name = confusables.Skeleton(name)
	}
	return casefoldSkeleton(name)
}
