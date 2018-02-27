// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package connection_limits

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

// LimiterConfig controls the automated connection limits.
type LimiterConfig struct {
	Enabled        bool
	CidrLenIPv4    int `yaml:"cidr-len-ipv4"`
	CidrLenIPv6    int `yaml:"cidr-len-ipv6"`
	ConnsPerSubnet int `yaml:"connections-per-subnet"`
	IPsPerSubnet   int `yaml:"ips-per-subnet"` // legacy name for ConnsPerSubnet
	Exempted       []string
}

var (
	errTooManyClients = errors.New("Too many clients in subnet")
)

// Limiter manages the automated client connection limits.
type Limiter struct {
	sync.Mutex

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
func (cl *Limiter) maskAddr(addr net.IP) net.IP {
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
func (cl *Limiter) AddClient(addr net.IP, force bool) error {
	cl.Lock()
	defer cl.Unlock()

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
func (cl *Limiter) RemoveClient(addr net.IP) {
	cl.Lock()
	defer cl.Unlock()

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

// NewLimiter returns a new connection limit handler.
// The handler is functional, but disabled; it can be enabled via `ApplyConfig`.
func NewLimiter() *Limiter {
	var cl Limiter

	// initialize empty population; all other state is configurable
	cl.population = make(map[string]int)

	return &cl
}

// ApplyConfig atomically applies a config update to a connection limit handler
func (cl *Limiter) ApplyConfig(config LimiterConfig) error {
	// assemble exempted nets
	exemptedIPs := make(map[string]bool)
	var exemptedNets []net.IPNet
	for _, cidr := range config.Exempted {
		ipaddr := net.ParseIP(cidr)
		_, netaddr, err := net.ParseCIDR(cidr)

		if ipaddr == nil && err != nil {
			return fmt.Errorf("Could not parse exempted IP/network [%s]", cidr)
		}

		if ipaddr != nil {
			exemptedIPs[ipaddr.String()] = true
		} else {
			exemptedNets = append(exemptedNets, *netaddr)
		}
	}

	cl.Lock()
	defer cl.Unlock()

	cl.enabled = config.Enabled
	cl.ipv4Mask = net.CIDRMask(config.CidrLenIPv4, 32)
	cl.ipv6Mask = net.CIDRMask(config.CidrLenIPv6, 128)
	// subnetLimit is explicitly NOT capped at a minimum of one.
	// this is so that CL config can be used to allow ONLY clients from exempted IPs/nets
	cl.subnetLimit = config.ConnsPerSubnet
	// but: check if the current key was left unset, but the legacy was set:
	if cl.subnetLimit == 0 && config.IPsPerSubnet != 0 {
		cl.subnetLimit = config.IPsPerSubnet
	}
	cl.exemptedIPs = exemptedIPs
	cl.exemptedNets = exemptedNets

	return nil
}
