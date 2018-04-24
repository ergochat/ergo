// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package utils

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
	if AddrIsUnix(addr) {
		return "localhost"
	}
	return LookupHostname(IPString(addr))
}

// AddrIsLocal returns whether the address is from a trusted local connection (loopback or unix).
func AddrIsLocal(addr net.Addr) bool {
	if tcpaddr, ok := addr.(*net.TCPAddr); ok {
		return tcpaddr.IP.IsLoopback()
	}
	_, ok := addr.(*net.UnixAddr)
	return ok
}

// AddrToIP returns the IP address for a net.Addr, or nil if it's a unix domain socket.
func AddrToIP(addr net.Addr) net.IP {
	if tcpaddr, ok := addr.(*net.TCPAddr); ok {
		return tcpaddr.IP
	}
	return nil
}

// AddrIsUnix returns whether the address is a unix domain socket.
func AddrIsUnix(addr net.Addr) bool {
	_, ok := addr.(*net.UnixAddr)
	return ok
}

// LookupHostname returns the hostname for `addr` if it has one. Otherwise, just returns `addr`.
func LookupHostname(addr string) string {
	names, err := net.LookupAddr(addr)
	if err == nil && len(names) > 0 {
		candidate := strings.TrimSuffix(names[0], ".")
		if IsHostname(candidate) {
			return candidate
		}
	}

	// return original address if no hostname found
	if len(addr) > 0 && addr[0] == ':' {
		// fix for IPv6 hostnames (so they don't start with a colon), same as all other IRCds
		addr = "0" + addr
	}
	return addr
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

// ReverseAddress returns IPv4 addresses reversed
func ReverseAddress(ip net.IP) string {
	// This is a IPv4 address
	if ip.To4() != nil {
		address := strings.Split(ip.String(), ".")

		for i, j := 0, len(address)-1; i < j; i, j = i+1, j-1 {
			address[i], address[j] = address[j], address[i]
		}

		return strings.Join(address, ".")
	}

	// fallback to returning the String of IP if it is not an IPv4 address
	return ip.String()
}
