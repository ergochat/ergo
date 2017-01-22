// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"errors"
	"strings"

	"golang.org/x/text/secure/precis"
)

const (
	casemappingName = "rfc7613"
)

var (
	errInvalidCharacter = errors.New("Invalid character")
	errEmpty            = errors.New("String is empty")
)

// Casefold returns a casefolded string, without doing any name or channel character checks.
func Casefold(str string) (string, error) {
	return precis.UsernameCaseMapped.CompareKey(str)
}

// CasefoldChannel returns a casefolded version of a channel name.
func CasefoldChannel(name string) (string, error) {
	lowered, err := Casefold(name)

	if err != nil {
		return "", err
	} else if len(lowered) == 0 {
		return "", errEmpty
	}

	if lowered[0] != '#' {
		return "", errInvalidCharacter
	}

	// space can't be used
	// , is used as a separator
	// * is used in mask matching
	// ? is used in mask matching
	if strings.Contains(lowered, " ") || strings.Contains(lowered, ",") ||
		strings.Contains(lowered, "*") || strings.Contains(lowered, "?") {
		return "", errInvalidCharacter
	}

	return lowered, err
}

// CasefoldName returns a casefolded version of a nick/user name.
func CasefoldName(name string) (string, error) {
	lowered, err := Casefold(name)

	if err != nil {
		return "", err
	} else if len(lowered) == 0 {
		return "", errEmpty
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
	if strings.Contains(lowered, " ") || strings.Contains(lowered, ",") ||
		strings.Contains(lowered, "*") || strings.Contains(lowered, "?") ||
		strings.Contains(lowered, ".") || strings.Contains(lowered, "!") ||
		strings.Contains(lowered, "@") ||
		strings.Contains("#~&@%+-", string(lowered[0])) {
		return "", errInvalidCharacter
	}

	return lowered, err
}
