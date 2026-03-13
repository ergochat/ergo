//go:build i18n

package i18n

import (
	"errors"
	"regexp"
	"strings"

	"github.com/ergochat/confusables"
	"golang.org/x/text/cases"
	"golang.org/x/text/secure/precis"
	"golang.org/x/text/unicode/norm"
	"golang.org/x/text/width"
)

const (
	Enabled = true

	// 1.x configurations don't have a server.casemapping field, but
	// expect PRECIS. however, technically it's not this value that
	// causes them to get PRECIS, it's that PRECIS is the zero value of
	// Casemapping (so that's how the YAML deserializes when the field
	// is missing).
	DefaultCasemapping = CasemappingPRECIS
)

var (
	// reviving the old ergonomadic nickname regex:
	// in permissive mode, allow arbitrary letters, numbers, punctuation, and symbols
	permissiveCharsRegex = regexp.MustCompile(`^[\pL\pN\pP\pS]*$`)
)

// String Errors
var (
	errCouldNotStabilize = errors.New("Could not stabilize string while casefolding")
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

func foldPRECIS(str string) (result string, err error) {
	return iterateFolding(precis.UsernameCaseMapped, str)
}

func foldPermissive(str string) (result string, err error) {
	if !permissiveCharsRegex.MatchString(str) {
		return "", errInvalidCharacter
	}
	// YOLO
	str = norm.NFD.String(str)
	str = cases.Fold().String(str)
	str = norm.NFD.String(str)
	return str, nil
}

var (
	rfc1459Replacer       = strings.NewReplacer("[", "{", "]", "}", "\\", "|", "~", "^")
	rfc1459StrictReplacer = strings.NewReplacer("[", "{", "]", "}", "\\", "|")
)

func foldRFC1459(str string, strict bool) (result string, err error) {
	asciiFold, err := foldASCII(str)
	if err != nil {
		return "", err
	}
	replacer := rfc1459Replacer
	if strict {
		replacer = rfc1459StrictReplacer
	}
	return replacer.Replace(asciiFold), nil
}

func CasefoldWithSetting(str string, setting Casemapping) (string, error) {
	switch setting {
	default:
		return foldPRECIS(str)
	case CasemappingASCII:
		return foldASCII(str)
	case CasemappingPermissive:
		return foldPermissive(str)
	case CasemappingRFC1459:
		return foldRFC1459(str, false)
	case CasemappingRFC1459Strict:
		return foldRFC1459(str, true)
	}
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
	return cases.Fold().String(name), nil
}
