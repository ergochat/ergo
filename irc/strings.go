package irc

import (
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

var (
	// regexps
	ChannelNameExpr = regexp.MustCompile(`^[&!#+][\pL\pN]{1,63}$`)
	NicknameExpr    = regexp.MustCompile("^[\\pL\\pN\\pP\\pS]{1,32}$")
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
	// , is used as a separator by the protocol
	// # is a channel prefix
	// @+ are channel membership prefixes
	if namestr == "*" || strings.Contains(namestr, ",") || strings.Contains("#@+", string(namestr[0])) {
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
