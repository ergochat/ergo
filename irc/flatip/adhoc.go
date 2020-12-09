// Copyright 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// Released under the MIT license

package flatip

// begin ad-hoc utilities

// ParseToNormalizedNet attempts to interpret a string either as an IP
// network in CIDR notation, returning an IPNet, or as an IP address,
// returning an IPNet that contains only that address.
func ParseToNormalizedNet(netstr string) (ipnet IPNet, err error) {
	_, ipnet, err = ParseCIDR(netstr)
	if err == nil {
		return
	}
	ip, err := ParseIP(netstr)
	if err == nil {
		ipnet.IP = ip
		ipnet.PrefixLen = 128
	}
	return
}

// IPInNets is a convenience function for testing whether an IP is contained
// in any member of a slice of IPNet's.
func IPInNets(addr IP, nets []IPNet) bool {
	for _, net := range nets {
		if net.Contains(addr) {
			return true
		}
	}
	return false
}
