// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
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
	errCouldNotStabilize = errors.New("Could not stabilize string while casefolding")
	errInvalidCharacter  = errors.New("Invalid character")
	errEmpty             = errors.New("String is empty")
)

// Casefold returns a casefolded string, without doing any name or channel character checks.
func Casefold(str string) (string, error) {
	var err error
	oldStr := str
	// follow the stabilizing rules laid out here:
	// https://tools.ietf.org/html/draft-ietf-precis-7564bis-10.html#section-7
	for i := 0; i < 4; i++ {
		str, err = precis.UsernameCaseMapped.CompareKey(str)
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
	if strings.ContainsAny(lowered, " ,*?") {
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
	if strings.ContainsAny(lowered, " ,*?.!@:") || strings.ContainsAny(string(lowered[0]), "#~&@%+-") {
		return "", errInvalidCharacter
	}

	return lowered, err
}
