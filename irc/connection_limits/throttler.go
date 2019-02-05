// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package connection_limits

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/oragono/oragono/irc/utils"
)

// ThrottlerConfig controls the automated connection throttling.
type ThrottlerConfig struct {
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
	Start time.Time
	Count int
}

// GenericThrottle allows enforcing limits of the form
// "at most X events per time window of duration Y"
type GenericThrottle struct {
	ThrottleDetails // variable state: what events have been seen
	// these are constant after creation:
	Duration time.Duration // window length to consider
	Limit    int           // number of events allowed per window
}

// Touch checks whether an additional event is allowed:
// it either denies it (by returning false) or allows it (by returning true)
// and records it
func (g *GenericThrottle) Touch() (throttled bool, remainingTime time.Duration) {
	return g.touch(time.Now())
}

func (g *GenericThrottle) touch(now time.Time) (throttled bool, remainingTime time.Duration) {
	if g.Limit == 0 {
		return // limit of 0 disables throttling
	}

	elapsed := now.Sub(g.Start)
	if elapsed > g.Duration {
		// reset window, record the operation
		g.Start = now
		g.Count = 1
		return false, 0
	} else if g.Count >= g.Limit {
		// we are throttled
		return true, g.Start.Add(g.Duration).Sub(now)
	} else {
		// we are not throttled, record the operation
		g.Count += 1
		return false, 0
	}
}

// Throttler manages automated client connection throttling.
type Throttler struct {
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

	// exemptedNets holds networks that are exempt from limits
	exemptedNets []net.IPNet
}

// maskAddr masks the given IPv4/6 address with our cidr limit masks.
func (ct *Throttler) maskAddr(addr net.IP) net.IP {
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
func (ct *Throttler) ResetFor(addr net.IP) {
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
func (ct *Throttler) AddClient(addr net.IP) error {
	ct.Lock()
	defer ct.Unlock()

	if !ct.enabled {
		return nil
	}

	// check exempted lists
	if utils.IPInNets(addr, ct.exemptedNets) {
		return nil
	}

	// check throttle
	ct.maskAddr(addr)
	addrString := addr.String()

	details := ct.population[addrString] // retrieve mutable throttle state from the map
	// add in constant state to process the limiting operation
	g := GenericThrottle{
		ThrottleDetails: details,
		Duration:        ct.duration,
		Limit:           ct.subnetLimit,
	}
	throttled, _ := g.Touch()                     // actually check the limit
	ct.population[addrString] = g.ThrottleDetails // store modified mutable state

	if throttled {
		return errTooManyClients
	} else {
		return nil
	}
}

func (ct *Throttler) BanDuration() time.Duration {
	ct.RLock()
	defer ct.RUnlock()

	return ct.banDuration
}

func (ct *Throttler) BanMessage() string {
	ct.RLock()
	defer ct.RUnlock()

	return ct.banMessage
}

// NewThrottler returns a new client connection throttler.
// The throttler is functional, but disabled; it can be enabled via `ApplyConfig`.
func NewThrottler() *Throttler {
	var ct Throttler

	// initialize empty population; all other state is configurable
	ct.population = make(map[string]ThrottleDetails)

	return &ct
}

// ApplyConfig atomically applies a config update to a throttler
func (ct *Throttler) ApplyConfig(config ThrottlerConfig) error {
	// assemble exempted nets
	exemptedNets, err := utils.ParseNetList(config.Exempted)
	if err != nil {
		return fmt.Errorf("Could not parse throttle exemption list: %v", err.Error())
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
	ct.exemptedNets = exemptedNets

	return nil
}
