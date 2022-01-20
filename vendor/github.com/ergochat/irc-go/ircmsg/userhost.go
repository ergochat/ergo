// written by Daniel Oaks <daniel@danieloaks.net>
// released under the ISC license

package ircmsg

import (
	"errors"
	"strings"
)

var (
	MalformedNUH = errors.New("NUH is malformed")
)

// NUH holds a parsed name!user@host source ("prefix") of an IRC message.
// The Name member will be either a nickname (in the case of a user-initiated
// message) or a server name (in the case of a server-initiated numeric,
// command, or NOTICE).
type NUH struct {
	Name string
	User string
	Host string
}

// ParseNUH parses a NUH source of an IRC message into its constituent parts;
// name (nickname or server name), username, and hostname.
func ParseNUH(in string) (out NUH, err error) {
	if len(in) == 0 {
		return out, MalformedNUH
	}

	hostStart := strings.IndexByte(in, '@')
	if hostStart != -1 {
		out.Host = in[hostStart+1:]
		in = in[:hostStart]
	}
	userStart := strings.IndexByte(in, '!')
	if userStart != -1 {
		out.User = in[userStart+1:]
		in = in[:userStart]
	}
	out.Name = in

	return
}

// Canonical returns the canonical string representation of the NUH.
func (nuh *NUH) Canonical() (result string) {
	var out strings.Builder
	out.Grow(len(nuh.Name) + len(nuh.User) + len(nuh.Host) + 2)
	out.WriteString(nuh.Name)
	if len(nuh.User) != 0 {
		out.WriteByte('!')
		out.WriteString(nuh.User)
	}
	if len(nuh.Host) != 0 {
		out.WriteByte('@')
		out.WriteString(nuh.Host)
	}
	return out.String()
}
