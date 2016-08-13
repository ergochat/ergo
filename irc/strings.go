// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

var (
	// regexps
	// these get replaced with real regexes at server load time

	ChannelNameExpr = regexp.MustCompile("^$")
	NicknameExpr    = regexp.MustCompile("^$")
)

// Names are normalized and canonicalized to remove formatting marks
// and simplify usage. They are things like hostnames and usermasks.
type Name string

func NewName(str string) Name {
	return Name(norm.NFKC.String(str))
}

func NewNames(strs []string) []Name {
	names := make([]Name, len(strs))
	for index, str := range strs {
		names[index] = NewName(str)
	}
	return names
}

// tests

func (name Name) IsChannel() bool {
	return ChannelNameExpr.MatchString(name.String())
}

func (name Name) IsNickname() bool {
	namestr := name.String()
	// * is used for unregistered clients
	// * is used for mask matching
	// ? is used for mask matching
	// . is used to denote server names
	// , is used as a separator by the protocol
	// ! separates username from nickname
	// @ separates nick+user from hostname
	// # is a channel prefix
	// ~&@%+ are channel membership prefixes
	// - is typically disallowed from first char of nicknames
	// nicknames can't start with digits
	if strings.Contains(namestr, "*") || strings.Contains(namestr, "?") ||
		strings.Contains(namestr, ".") || strings.Contains(namestr, ",") ||
		strings.Contains(namestr, "!") || strings.Contains(namestr, "@") ||
		strings.Contains("#~&@%+-1234567890", string(namestr[0])) {
		return false
	}
	// names that look like hostnames are restricted to servers, as with other ircds
	if IsHostname(namestr) {
		return false
	}
	return NicknameExpr.MatchString(namestr)
}

// conversions

func (name Name) String() string {
	return string(name)
}

func (name Name) ToLower() Name {
	return Name(strings.ToLower(name.String()))
}

// It's safe to coerce a Name to Text. Name is a strict subset of Text.
func (name Name) Text() Text {
	return Text(name)
}

// Text is PRIVMSG, NOTICE, or TOPIC data. It's canonicalized UTF8
// data to simplify but keeps all formatting.
type Text string

func NewText(str string) Text {
	return Text(norm.NFC.String(str))
}

func (text Text) String() string {
	return string(text)
}

// CTCPText is text suitably escaped for CTCP.
type CTCPText string

var ctcpEscaper = strings.NewReplacer("\x00", "\x200", "\n", "\x20n", "\r", "\x20r")

func NewCTCPText(str string) CTCPText {
	return CTCPText(ctcpEscaper.Replace(str))
}
