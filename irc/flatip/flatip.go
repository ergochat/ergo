// Copyright 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// Copyright 2009 The Go Authors
// Released under the MIT license

package flatip

import (
	"bytes"
	"errors"
	"net"
)

var (
	v4InV6Prefix = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}

	IPv6loopback = IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	IPv6zero     = IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	IPv4zero     = IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0}

	ErrInvalidIPString = errors.New("String could not be interpreted as an IP address")
)

// packed versions of net.IP and net.IPNet; these are pure value types,
// so they can be compared with == and used as map keys.

// IP is a 128-bit representation of an IP address, using the 4-in-6 mapping
// to represent IPv4 addresses.
type IP [16]byte

// IPNet is a IP network. In a valid value, all bits after PrefixLen are zeroes.
type IPNet struct {
	IP
	PrefixLen uint8
}

// NetIP converts an IP into a net.IP.
func (ip IP) NetIP() (result net.IP) {
	result = make(net.IP, 16)
	copy(result[:], ip[:])
	return
}

// FromNetIP converts a net.IP into an IP.
func FromNetIP(ip net.IP) (result IP) {
	if len(ip) == 16 {
		copy(result[:], ip[:])
	} else {
		result[10] = 0xff
		result[11] = 0xff
		copy(result[12:], ip[:])
	}
	return
}

// IPv4 returns the IP address representation of a.b.c.d
func IPv4(a, b, c, d byte) (result IP) {
	copy(result[:12], v4InV6Prefix)
	result[12] = a
	result[13] = b
	result[14] = c
	result[15] = d
	return
}

// ParseIP parses a string representation of an IP address into an IP.
// Unlike net.ParseIP, it returns an error instead of a zero value on failure,
// since the zero value of `IP` is a representation of a valid IP (::0, the
// IPv6 "unspecified address").
func ParseIP(ipstr string) (ip IP, err error) {
	// TODO reimplement this without net.ParseIP
	netip := net.ParseIP(ipstr)
	if netip == nil {
		err = ErrInvalidIPString
		return
	}
	netip = netip.To16()
	copy(ip[:], netip)
	return
}

// String returns the string representation of an IP
func (ip IP) String() string {
	// TODO reimplement this without using (net.IP).String()
	return (net.IP)(ip[:]).String()
}

// IsIPv4 returns whether the IP is an IPv4 address.
func (ip IP) IsIPv4() bool {
	return bytes.Equal(ip[:12], v4InV6Prefix)
}

// IsLoopback returns whether the IP is a loopback address.
func (ip IP) IsLoopback() bool {
	if ip.IsIPv4() {
		return ip[12] == 127
	} else {
		return ip == IPv6loopback
	}
}

func (ip IP) IsUnspecified() bool {
	return ip == IPv4zero || ip == IPv6zero
}

func rawCidrMask(length int) (m IP) {
	n := uint(length)
	for i := 0; i < 16; i++ {
		if n >= 8 {
			m[i] = 0xff
			n -= 8
			continue
		}
		m[i] = ^byte(0xff >> n)
		return
	}
	return
}

func (ip IP) applyMask(mask IP) (result IP) {
	for i := 0; i < 16; i += 1 {
		result[i] = ip[i] & mask[i]
	}
	return
}

func cidrMask(ones, bits int) (result IP) {
	switch bits {
	case 32:
		return rawCidrMask(96 + ones)
	case 128:
		return rawCidrMask(ones)
	default:
		return
	}
}

// Mask returns the result of masking ip with the CIDR mask of
// length 'ones', out of a total of 'bits' (which must be either
// 32 for an IPv4 subnet or 128 for an IPv6 subnet).
func (ip IP) Mask(ones, bits int) (result IP) {
	return ip.applyMask(cidrMask(ones, bits))
}

// ToNetIPNet converts an IPNet into a net.IPNet.
func (cidr IPNet) ToNetIPNet() (result net.IPNet) {
	return net.IPNet{
		IP:   cidr.IP.NetIP(),
		Mask: net.CIDRMask(int(cidr.PrefixLen), 128),
	}
}

// Contains retuns whether the network contains `ip`.
func (cidr IPNet) Contains(ip IP) bool {
	maskedIP := ip.Mask(int(cidr.PrefixLen), 128)
	return cidr.IP == maskedIP
}

func (cidr IPNet) Size() (ones, bits int) {
	if cidr.IP.IsIPv4() {
		return int(cidr.PrefixLen) - 96, 32
	} else {
		return int(cidr.PrefixLen), 128
	}
}

// FromNetIPnet converts a net.IPNet into an IPNet.
func FromNetIPNet(network net.IPNet) (result IPNet) {
	ones, _ := network.Mask.Size()
	if len(network.IP) == 16 {
		copy(result.IP[:], network.IP[:])
	} else {
		result.IP[10] = 0xff
		result.IP[11] = 0xff
		copy(result.IP[12:], network.IP[:])
		ones += 96
	}
	// perform masking so that equal CIDRs are ==
	result.IP = result.IP.Mask(ones, 128)
	result.PrefixLen = uint8(ones)
	return
}

// String returns a string representation of an IPNet.
func (cidr IPNet) String() string {
	ip := make(net.IP, 16)
	copy(ip[:], cidr.IP[:])
	ipnet := net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(int(cidr.PrefixLen), 128),
	}
	return ipnet.String()
}

// HumanReadableString returns a string representation of an IPNet;
// if the network contains only a single IP address, it returns
// a representation of that address.
func (cidr IPNet) HumanReadableString() string {
	if cidr.PrefixLen == 128 {
		return cidr.IP.String()
	}
	return cidr.String()
}

// IsZero tests whether ipnet is the zero value of an IPNet, 0::0/0.
// Although this is a valid subnet, it can still be used as a sentinel
// value in some contexts.
func (ipnet IPNet) IsZero() bool {
	return ipnet == IPNet{}
}

// ParseCIDR parses a string representation of an IP network in CIDR notation,
// then returns it as an IPNet (along with the original, unmasked address).
func ParseCIDR(netstr string) (ip IP, ipnet IPNet, err error) {
	// TODO reimplement this without net.ParseCIDR
	nip, nipnet, err := net.ParseCIDR(netstr)
	if err != nil {
		return
	}
	return FromNetIP(nip), FromNetIPNet(*nipnet), nil
}
