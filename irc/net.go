package irc

import (
	"net"
	"strings"
)

func IPString(addr net.Addr) Name {
	addrStr := addr.String()
	ipaddr, _, err := net.SplitHostPort(addrStr)
	if err != nil {
		return Name(addrStr)
	}
	return Name(ipaddr)
}

func AddrLookupHostname(addr net.Addr) Name {
	return LookupHostname(IPString(addr))
}

func LookupHostname(addr Name) Name {
	names, err := net.LookupAddr(addr.String())
	if err != nil {
		return Name(addr)
	}

	hostname := strings.TrimSuffix(names[0], ".")
	return Name(hostname)
}

var allowedHostnameChars = "abcdefghijklmnopqrstuvwxyz1234567890-."

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
