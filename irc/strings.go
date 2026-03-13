// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"strings"

	"github.com/ergochat/ergo/irc/i18n"
	"github.com/ergochat/ergo/irc/utils"
)

const (
	precisUTF8MappingToken = "rfc8265"

	// space can't be used
	// , is used as a separator
	// * is used in mask matching
	// ? is used in mask matching
	// . denotes a server name
	// ! separates nickname from username
	// @ separates username from hostname
	// : means trailing
	protocolBreakingNameCharacters = " ,*?.!@:"

	// #1436: we discovered that these characters are problematic,
	// so we're disallowing them in new nicks/account names, but allowing
	// previously registered names
	disfavoredNameCharacters = `<>'";#`
)

// XXX this is a global variable without explicit synchronization.
// it gets set during the initial Server.applyConfig and cannot be changed by rehash:
// this happens-before all IRC connections and all casefolding operations.
var globalCasemappingSetting i18n.Casemapping = i18n.DefaultCasemapping

// XXX analogous unsynchronized global variable controlling utf8 validation
// if this is off, you get the traditional IRC behavior (relaying any valid RFC1459
// octets), and websocket listeners are disabled.
// if this is on, invalid utf8 inputs get a FAIL reply.
var globalUtf8EnforcementSetting bool

// Casefold returns a casefolded string, without doing any name or channel character checks.
func Casefold(str string) (string, error) {
	return i18n.CasefoldWithSetting(str, globalCasemappingSetting)
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

	// # is a channel prefix
	// ~&@%+ are channel membership prefixes
	// - I feel like disallowing
	if strings.ContainsAny(lowered, protocolBreakingNameCharacters) || strings.ContainsAny(string(lowered[0]), "#~&@%+-") {
		return "", errInvalidCharacter
	}

	return lowered, err
}

// CasefoldTarget returns a casefolded version of an IRC target, i.e.
// it determines whether the target is a channel name or nickname and
// applies the appropriate casefolding rules.
func CasefoldTarget(name string) (string, error) {
	if strings.HasPrefix(name, "#") {
		return CasefoldChannel(name)
	} else {
		return CasefoldName(name)
	}
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
// homoglyphic / confusable identifiers.
func Skeleton(name string) (string, error) {
	switch globalCasemappingSetting {
	default:
		return i18n.Skeleton(name)
	case i18n.CasemappingASCII, i18n.CasemappingRFC1459, i18n.CasemappingRFC1459Strict:
		// identity function is fine because we independently case-normalize in Casefold
		return name, nil
	}
}

// maps a nickmask fragment to an expanded, casefolded wildcard:
// Shivaram@good-fortune -> *!shivaram@good-fortune
// EDMUND -> edmund!*@*
func CanonicalizeMaskWildcard(userhost string) (expanded string, err error) {
	userhost = strings.TrimSpace(userhost)
	var nick, user, host string
	bangIndex := strings.IndexByte(userhost, '!')
	strudelIndex := strings.IndexByte(userhost, '@')

	if bangIndex != -1 && bangIndex < strudelIndex {
		nick = userhost[:bangIndex]
		user = userhost[bangIndex+1 : strudelIndex]
		host = userhost[strudelIndex+1:]
	} else if bangIndex != -1 && strudelIndex == -1 {
		nick = userhost[:bangIndex]
		user = userhost[bangIndex+1:]
	} else if bangIndex != -1 && strudelIndex < bangIndex {
		// @ before !, fail
		return "", errNicknameInvalid
	} else if bangIndex == -1 && strudelIndex != -1 {
		user = userhost[:strudelIndex]
		host = userhost[strudelIndex+1:]
	} else if bangIndex == -1 && strudelIndex == -1 {
		nick = userhost
	} else {
		// shouldn't be possible
		return "", errInvalidParams
	}

	if nick == "" {
		nick = "*"
	}
	if nick != "*" {
		// XXX wildcards are not accepted with most unicode nicks,
		// because the * character breaks casefolding
		nick, err = Casefold(nick)
		if err != nil {
			return "", err
		}
	}
	if user == "" {
		user = "*"
	}
	if user != "*" {
		user = strings.ToLower(user)
	}
	if host == "" {
		host = "*"
	}
	if host != "*" {
		host = strings.ToLower(host)
	}
	expanded = fmt.Sprintf("%s!%s@%s", nick, user, host)
	if utils.SafeErrorParam(expanded) != expanded {
		err = errInvalidCharacter
	}
	return
}

func IsPrintableASCII(str string) bool {
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

// Reduce, e.g., `alice!~u@host` to `alice`
func NUHToNick(nuh string) (nick string) {
	if idx := strings.IndexByte(nuh, '!'); idx != -1 {
		return nuh[0:idx]
	}
	return nuh
}
