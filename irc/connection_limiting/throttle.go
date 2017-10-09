// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package connection_limiting

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ConnectionThrottleConfig controls the automated connection throttling.
type ConnectionThrottleConfig struct {
	Enabled            bool
	CidrLenIPv4        int           `yaml:"cidr-len-ipv4"`
	CidrLenIPv6        int           `yaml:"cidr-len-ipv6"`
	ConnectionsPerCidr int           `yaml:"max-connections"`
	DurationString     string        `yaml:"duration"`
	Duration           time.Duration `yaml:"duration-time"`
	BanDurationString  string        `yaml:"ban-duration"`
	BanDuration        time.Duration
	BanMessage         string `yaml:"ban-message"`
	Exempted           []string
}

// ThrottleDetails holds the connection-throttling details for a subnet/IP.
type ThrottleDetails struct {
	Start       time.Time
	ClientCount int
}

// ConnectionThrottle manages automated client connection throttling.
type ConnectionThrottle struct {
	sync.RWMutex

	enabled     bool
	ipv4Mask    net.IPMask
	ipv6Mask    net.IPMask
	subnetLimit int
	duration    time.Duration
	population  map[string]ThrottleDetails

	// used by the server to ban clients that go over this limit
	banDuration time.Duration
	banMessage  string

	// exemptedIPs holds IPs that are exempt from limits
	exemptedIPs map[string]bool
	// exemptedNets holds networks that are exempt from limits
	exemptedNets []net.IPNet
}

// maskAddr masks the given IPv4/6 address with our cidr limit masks.
func (ct *ConnectionThrottle) maskAddr(addr net.IP) net.IP {
	if addr.To4() == nil {
		// IPv6 addr
		addr = addr.Mask(ct.ipv6Mask)
	} else {
		// IPv4 addr
		addr = addr.Mask(ct.ipv4Mask)
	}

	return addr
}

// ResetFor removes any existing count for the given address.
func (ct *ConnectionThrottle) ResetFor(addr net.IP) {
	ct.Lock()
	defer ct.Unlock()

	if !ct.enabled {
		return
	}

	// remove
	ct.maskAddr(addr)
	addrString := addr.String()
	delete(ct.population, addrString)
}

// AddClient introduces a new client connection if possible. If we can't, throws an error instead.
func (ct *ConnectionThrottle) AddClient(addr net.IP) error {
	ct.Lock()
	defer ct.Unlock()

	if !ct.enabled {
		return nil
	}

	// check exempted lists
	if ct.exemptedIPs[addr.String()] {
		return nil
	}
	for _, ex := range ct.exemptedNets {
		if ex.Contains(addr) {
			return nil
		}
	}

	// check throttle
	ct.maskAddr(addr)
	addrString := addr.String()

	details, exists := ct.population[addrString]
	if !exists || details.Start.Add(ct.duration).Before(time.Now()) {
		details = ThrottleDetails{
			Start: time.Now(),
		}
	}

	if details.ClientCount+1 > ct.subnetLimit {
		return errTooManyClients
	}

	details.ClientCount++
	ct.population[addrString] = details

	return nil
}

func (ct *ConnectionThrottle) BanDuration() time.Duration {
	ct.RLock()
	defer ct.RUnlock()

	return ct.banDuration
}

func (ct *ConnectionThrottle) BanMessage() string {
	ct.RLock()
	defer ct.RUnlock()

	return ct.banMessage
}

// NewConnectionThrottle returns a new client connection throttler.
// The throttler is functional, but disabled; it can be enabled via `ApplyConfig`.
func NewConnectionThrottle() *ConnectionThrottle {
	var ct ConnectionThrottle

	// initialize empty population; all other state is configurable
	ct.population = make(map[string]ThrottleDetails)

	return &ct
}

// ApplyConfig atomically applies a config update to a throttler
func (ct *ConnectionThrottle) ApplyConfig(config ConnectionThrottleConfig) error {
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

	ct.Lock()
	defer ct.Unlock()

	ct.enabled = config.Enabled
	ct.ipv4Mask = net.CIDRMask(config.CidrLenIPv4, 32)
	ct.ipv6Mask = net.CIDRMask(config.CidrLenIPv6, 128)
	ct.subnetLimit = config.ConnectionsPerCidr
	ct.duration = config.Duration
	ct.banDuration = config.BanDuration
	ct.banMessage = config.BanMessage
	ct.exemptedIPs = exemptedIPs
	ct.exemptedNets = exemptedNets

	return nil
}
