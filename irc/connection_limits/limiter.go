// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package connection_limits

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/oragono/oragono/irc/utils"
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

	// exemptedNets holds networks that are exempt from limits
	exemptedNets []net.IPNet
}

// addrToKey canonicalizes `addr` to a string key.
func addrToKey(addr net.IP, v4Mask net.IPMask, v6Mask net.IPMask) string {
	if addr.To4() != nil {
		addr = addr.Mask(v4Mask) // IP.Mask() handles the 4-in-6 mapping for us
	} else {
		addr = addr.Mask(v6Mask)
	}
	return addr.String()
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
	if utils.IPInNets(addr, cl.exemptedNets) {
		return nil
	}

	// check population
	addrString := addrToKey(addr, cl.ipv4Mask, cl.ipv6Mask)

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

	addrString := addrToKey(addr, cl.ipv4Mask, cl.ipv6Mask)
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
	exemptedNets, err := utils.ParseNetList(config.Exempted)
	if err != nil {
		return fmt.Errorf("Could not parse limiter exemption list: %v", err.Error())
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
	cl.exemptedNets = exemptedNets

	return nil
}
