// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package utils

import (
	"net"
	"regexp"
	"strings"
)

var (
	// subnet mask for an ipv6 /128:
	mask128             = net.CIDRMask(128, 128)
	IPv4LoopbackAddress = net.ParseIP("127.0.0.1").To16()

	validHostnameLabelRegexp = regexp.MustCompile(`^[0-9A-Za-z.\-]+$`)
)

// AddrToIP returns the IP address for a net.Addr; unix domain sockets are treated as IPv4 loopback
func AddrToIP(addr net.Addr) net.IP {
	if tcpaddr, ok := addr.(*net.TCPAddr); ok {
		return tcpaddr.IP.To16()
	} else if _, ok := addr.(*net.UnixAddr); ok {
		return IPv4LoopbackAddress
	} else {
		return nil
	}
}

// IPStringToHostname converts a string representation of an IP address to an IRC-ready hostname
func IPStringToHostname(ipStr string) string {
	if 0 < len(ipStr) && ipStr[0] == ':' {
		// fix for IPv6 hostnames (so they don't start with a colon), same as all other IRCds
		ipStr = "0" + ipStr
	}
	return ipStr
}

// IsHostname returns whether we consider `name` a valid hostname.
func IsHostname(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if len(name) < 1 || len(name) > 253 {
		return false
	}

	// ensure each part of hostname is valid
	for _, part := range strings.Split(name, ".") {
		if len(part) < 1 || len(part) > 63 || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
		if !validHostnameLabelRegexp.MatchString(part) {
			return false
		}
	}

	return true
}

// IsServerName returns whether we consider `name` a valid IRC server name.
func IsServerName(name string) bool {
	// IRC server names specifically require a period
	return IsHostname(name) && strings.IndexByte(name, '.') != -1
}

// Convenience to test whether `ip` is contained in any of `nets`.
func IPInNets(ip net.IP, nets []net.IPNet) bool {
	for _, network := range nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
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

// Parse a list of IPs and nets as they would appear in one of our config
// files, e.g., proxy-allowed-from or a throttling exemption list.
func ParseNetList(netList []string) (nets []net.IPNet, err error) {
	var network net.IPNet
	for _, netStr := range netList {
		if netStr == "localhost" {
			ipv4Loopback, _ := NormalizedNetFromString("127.0.0.0/8")
			ipv6Loopback, _ := NormalizedNetFromString("::1/128")
			nets = append(nets, ipv4Loopback)
			nets = append(nets, ipv6Loopback)
			continue
		}
		network, err = NormalizedNetFromString(netStr)
		if err != nil {
			return
		} else {
			nets = append(nets, network)
		}
	}
	return
}

// Process the X-Forwarded-For header, validating against a list of trusted IPs.
// Returns the address that the request was forwarded for, or nil if no trustworthy
// data was available.
func HandleXForwardedFor(remoteAddr string, xForwardedFor string, whitelist []net.IPNet) (result net.IP) {
	// http.Request.RemoteAddr "has no defined format". with TCP it's typically "127.0.0.1:23784",
	// with unix domain it's typically "@"
	var remoteIP net.IP
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		remoteIP = IPv4LoopbackAddress
	} else {
		remoteIP = net.ParseIP(host)
	}

	if remoteIP == nil || !IPInNets(remoteIP, whitelist) {
		return remoteIP
	}

	// walk backwards through the X-Forwarded-For chain looking for an IP
	// that is *not* trusted. that means it was added by one of our trusted
	// forwarders (either remoteIP or something ahead of it in the chain)
	// and we can trust it:
	result = remoteIP
	forwardedIPs := strings.Split(xForwardedFor, ",")
	for i := len(forwardedIPs) - 1; i >= 0; i-- {
		proxiedIP := net.ParseIP(strings.TrimSpace(forwardedIPs[i]))
		if proxiedIP == nil {
			return
		} else if !IPInNets(proxiedIP, whitelist) {
			return proxiedIP
		} else {
			result = proxiedIP
		}
	}

	// no valid untrusted IPs were found in the chain;
	// return either the last valid and trusted IP (which must be the origin),
	// or nil:
	return
}

// LookupHostname does an (optionally reverse-confirmed) hostname lookup
// suitable for use as an IRC hostname. It falls back to a string
// representation of the IP address (again suitable for use as an IRC
// hostname).
func LookupHostname(ip net.IP, forwardConfirm bool) (hostname string, lookupSuccessful bool) {
	ipString := ip.String()
	var candidate string
	names, err := net.LookupAddr(ipString)
	if err == nil && 0 < len(names) {
		candidate = strings.TrimSuffix(names[0], ".")
	}
	if IsHostname(candidate) {
		if forwardConfirm {
			addrs, err := net.LookupHost(candidate)
			if err == nil {
				for _, addr := range addrs {
					if forwardIP := net.ParseIP(addr); ip.Equal(forwardIP) {
						hostname = candidate // successful forward confirmation
						break
					}
				}
			}
		} else {
			hostname = candidate
		}
	}

	if hostname != "" {
		return hostname, true
	} else {
		return IPStringToHostname(ipString), false
	}
}
