// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"net"
	"strings"
)

// IPString returns a simple IP string from the given net.Addr.
func IPString(addr net.Addr) string {
	addrStr := addr.String()
	ipaddr, _, err := net.SplitHostPort(addrStr)
	//TODO(dan): Why is this needed, does this happen?
	if err != nil {
		return addrStr
	}
	return ipaddr
}

// AddrLookupHostname returns the hostname (if possible) or address for the given `net.Addr`.
func AddrLookupHostname(addr net.Addr) string {
	return LookupHostname(IPString(addr))
}

// LookupHostname returns the hostname for `addr` if it has one. Otherwise, just returns `addr`.
func LookupHostname(addr string) string {
	names, err := net.LookupAddr(addr)
	if err != nil || len(names) < 1 || !IsHostname(names[0]) {
		// return original address if no hostname found
		if len(addr) > 0 && addr[0] == ':' {
			// fix for IPv6 hostnames (so they don't start with a colon), same as all other IRCds
			addr = "0" + addr
		}
		return addr
	}

	return names[0]
}

var allowedHostnameChars = "abcdefghijklmnopqrstuvwxyz1234567890-."

// IsHostname returns whether we consider `name` a valid hostname.
func IsHostname(name string) bool {
	// IRC hostnames specifically require a period
	if !strings.Contains(name, ".") || len(name) < 1 || len(name) > 253 {
		return false
	}

	// ensure each part of hostname is valid
	for _, part := range strings.Split(name, ".") {
		if len(part) < 1 || len(part) > 63 || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
	}

	// ensure all chars of hostname are valid
	for _, char := range strings.Split(strings.ToLower(name), "") {
		if !strings.Contains(allowedHostnameChars, char) {
			return false
		}
	}

	return true
}
