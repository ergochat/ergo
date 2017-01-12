// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"net"
)

var (
	errTooManyClients = errors.New("Too many clients in subnet")
)

// ConnectionLimits manages the automated client connection limits.
type ConnectionLimits struct {
	enabled  bool
	ipv4Mask net.IPMask
	ipv6Mask net.IPMask
	// subnetLimit is the maximum number of clients per subnet
	subnetLimit int
	// population holds IP -> count of clients connected from there
	population map[string]int

	// exemptedIPs holds IPs that are exempt from limits
	exemptedIPs map[string]bool
	// exemptedNets holds networks that are exempt from limits
	exemptedNets []net.IPNet
}

// maskAddr masks the given IPv4/6 address with our cidr limit masks.
func (cl *ConnectionLimits) maskAddr(addr net.IP) net.IP {
	if addr.To4() == nil {
		// IPv6 addr
		addr = addr.Mask(cl.ipv6Mask)
	} else {
		// IPv4 addr
		addr = addr.Mask(cl.ipv4Mask)
	}

	return addr
}

// AddClient adds a client to our population if possible. If we can't, throws an error instead.
// 'force' is used to add already-existing clients (i.e. ones that are already on the network).
func (cl *ConnectionLimits) AddClient(addr net.IP, force bool) error {
	if !cl.enabled {
		return nil
	}

	// check exempted lists
	// we don't track populations for exempted addresses or nets - this is by design
	if cl.exemptedIPs[addr.String()] {
		return nil
	}
	for _, ex := range cl.exemptedNets {
		if ex.Contains(addr) {
			return nil
		}
	}

	// check population
	cl.maskAddr(addr)
	addrString := addr.String()

	if cl.population[addrString]+1 > cl.subnetLimit && !force {
		return errTooManyClients
	}

	cl.population[addrString] = cl.population[addrString] + 1

	return nil
}

// RemoveClient removes the given address from our population
func (cl *ConnectionLimits) RemoveClient(addr net.IP) {
	if !cl.enabled {
		return
	}

	addrString := addr.String()
	cl.population[addrString] = cl.population[addrString] - 1

	// safety limiter
	if cl.population[addrString] < 0 {
		cl.population[addrString] = 0
	}
}

// NewConnectionLimits returns a new connection limit handler.
func NewConnectionLimits(config ConnectionLimitsConfig) (*ConnectionLimits, error) {
	var cl ConnectionLimits
	cl.enabled = config.Enabled

	cl.population = make(map[string]int)
	cl.exemptedIPs = make(map[string]bool)

	cl.ipv4Mask = net.CIDRMask(config.CidrLenIPv4, 32)
	cl.ipv6Mask = net.CIDRMask(config.CidrLenIPv6, 128)
	// subnetLimit is explicitly NOT capped at a minimum of one.
	// this is so that CL config can be used to allow ONLY clients from exempted IPs/nets
	cl.subnetLimit = config.IPsPerCidr

	// assemble exempted nets
	for _, cidr := range config.Exempted {
		ipaddr := net.ParseIP(cidr)
		_, netaddr, err := net.ParseCIDR(cidr)

		if ipaddr == nil && err != nil {
			return nil, fmt.Errorf("Could not parse exempted IP/network [%s]", cidr)
		}

		if ipaddr != nil {
			cl.exemptedIPs[ipaddr.String()] = true
		} else {
			cl.exemptedNets = append(cl.exemptedNets, *netaddr)
		}
	}

	return &cl, nil
}
