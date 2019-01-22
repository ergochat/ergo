// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package utils

import (
	"net"
	"strings"
)

var (
	// subnet mask for an ipv6 /128:
	mask128 = net.CIDRMask(128, 128)
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

// NormalizeIPToNet represents an address (v4 or v6) as the v6 /128 CIDR
// containing only it.
func NormalizeIPToNet(addr net.IP) (network net.IPNet) {
	// represent ipv4 addresses as ipv6 addresses, using the 4-in-6 prefix
	// (actually this should be a no-op for any address returned by ParseIP)
	addr = addr.To16()
	// the network corresponding to this address is now an ipv6 /128:
	return net.IPNet{
		IP:   addr,
		Mask: mask128,
	}
}

// NormalizeNet normalizes an IPNet to a v6 CIDR, using the 4-in-6 prefix.
// (this is like IP.To16(), but for IPNet instead of IP)
func NormalizeNet(network net.IPNet) (result net.IPNet) {
	if len(network.IP) == 16 {
		return network
	}
	ones, _ := network.Mask.Size()
	return net.IPNet{
		IP: network.IP.To16(),
		// include the 96 bits of the 4-in-6 prefix
		Mask: net.CIDRMask(96+ones, 128),
	}
}

// Given a network, produce a human-readable string
// (i.e., CIDR if it's actually a network, IPv6 address if it's a v6 /128,
// dotted quad if it's a v4 /32).
func NetToNormalizedString(network net.IPNet) string {
	ones, bits := network.Mask.Size()
	if ones == bits && ones == len(network.IP)*8 {
		// either a /32 or a /128, output the address:
		return network.IP.String()
	}
	return network.String()
}

// Parse a human-readable description (an address or CIDR, either v4 or v6)
// into a normalized v6 net.IPNet.
func NormalizedNetFromString(str string) (result net.IPNet, err error) {
	_, network, err := net.ParseCIDR(str)
	if err == nil {
		return NormalizeNet(*network), nil
	}
	ip := net.ParseIP(str)
	if ip == nil {
		err = &net.AddrError{
			Err:  "Couldn't interpret as either CIDR or address",
			Addr: str,
		}
		return
	}
	return NormalizeIPToNet(ip), nil
}
