package i18n

import (
	"errors"
	"fmt"
	"strings"
)

// Casemapping represents a set of algorithm for case normalization
// and confusables prevention for IRC identifiers (nicknames and channel names)
type Casemapping uint

const (
	// "precis" is the default / zero value:
	// casefolding/validation: PRECIS + ircd restrictions (like no *)
	// confusables detection: standard skeleton algorithm
	CasemappingPRECIS Casemapping = iota
	// "ascii" is the traditional ircd behavior:
	// casefolding/validation: must be pure ASCII and follow ircd restrictions, ASCII lowercasing
	// confusables detection: none
	CasemappingASCII
	// "permissive" is an insecure mode:
	// casefolding/validation: arbitrary unicodes that follow ircd restrictions, unicode casefolding
	// confusables detection: standard skeleton algorithm (which may be ineffective
	// over the larger set of permitted identifiers)
	CasemappingPermissive
	// rfc1459 is a legacy mapping as defined here: https://modern.ircdocs.horse/#casemapping-parameter
	CasemappingRFC1459
	// rfc1459-strict is a legacy mapping as defined here: https://modern.ircdocs.horse/#casemapping-parameter
	CasemappingRFC1459Strict
)

var (
	errInvalidCharacter = errors.New("Invalid character")
)

func (cm *Casemapping) UnmarshalYAML(unmarshal func(interface{}) error) (err error) {
	var orig string
	if err = unmarshal(&orig); err != nil {
		return err
	}

	var result Casemapping
	switch strings.ToLower(orig) {
	case "ascii":
		result = CasemappingASCII
	case "precis", "rfc7613", "rfc8265":
		result = CasemappingPRECIS
	case "permissive", "fun":
		result = CasemappingPermissive
	case "rfc1459":
		result = CasemappingRFC1459
	case "rfc1459-strict":
		result = CasemappingRFC1459Strict
	default:
		return fmt.Errorf("invalid casemapping value: %s", orig)
	}
	*cm = result
	return nil
}

func isPrintableASCII(str string) bool {
	for i := 0; i < len(str); i++ {
		// allow space here because it's technically printable;
		// it will be disallowed later by CasefoldName/CasefoldChannel
		chr := str[i]
		if chr < ' ' || chr > '~' {
			return false
		}
	}
	return true
}

func foldASCII(str string) (result string, err error) {
	if !isPrintableASCII(str) {
		return "", errInvalidCharacter
	}
	return strings.ToLower(str), nil
}
