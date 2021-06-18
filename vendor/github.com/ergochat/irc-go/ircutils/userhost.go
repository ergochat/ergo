// written by Daniel Oaks <daniel@danieloaks.net>
// released under the ISC license

package ircutils

import "strings"

// UserHost holds a username+host combination
type UserHost struct {
	Nick string
	User string
	Host string
}

// ParseUserhost takes a userhost string and returns a UserHost instance.
func ParseUserhost(userhost string) UserHost {
	var uh UserHost

	if len(userhost) == 0 {
		return uh
	}

	if strings.Contains(userhost, "!") {
		usersplit := strings.SplitN(userhost, "!", 2)
		var rest string
		if len(usersplit) == 2 {
			uh.Nick = usersplit[0]
			rest = usersplit[1]
		} else {
			rest = usersplit[0]
		}

		hostsplit := strings.SplitN(rest, "@", 2)
		if len(hostsplit) == 2 {
			uh.User = hostsplit[0]
			uh.Host = hostsplit[1]
		} else {
			uh.User = hostsplit[0]
		}
	} else {
		hostsplit := strings.SplitN(userhost, "@", 2)
		if len(hostsplit) == 2 {
			uh.Nick = hostsplit[0]
			uh.Host = hostsplit[1]
		} else {
			uh.User = hostsplit[0]
		}
	}

	return uh
}

// // Canonical returns the canonical string representation of the userhost.
// func (uh *UserHost) Canonical() string {
// 	return ""
// }
