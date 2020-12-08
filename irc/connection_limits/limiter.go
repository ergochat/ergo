// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package connection_limits

import (
	"crypto/md5"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/oragono/oragono/irc/flatip"
	"github.com/oragono/oragono/irc/utils"
)

var (
	ErrLimitExceeded    = errors.New("too many concurrent connections")
	ErrThrottleExceeded = errors.New("too many recent connection attempts")
)

type CustomLimitConfig struct {
	Nets          []string
	MaxConcurrent int `yaml:"max-concurrent-connections"`
	MaxPerWindow  int `yaml:"max-connections-per-window"`
}

// tuples the key-value pair of a CIDR and its custom limit/throttle values
type customLimit struct {
	name          [16]byte
	maxConcurrent int
	maxPerWindow  int
	nets          []flatip.IPNet
}

type limiterKey struct {
	maskedIP  flatip.IP
	prefixLen uint8 // 0 for the fake nets we generate for custom limits
}

// LimiterConfig controls the automated connection limits.
// rawLimiterConfig contains all the YAML-visible fields;
// LimiterConfig contains additional denormalized private fields
type rawLimiterConfig struct {
	Count         bool
	MaxConcurrent int `yaml:"max-concurrent-connections"`

	Throttle     bool
	Window       time.Duration
	MaxPerWindow int           `yaml:"max-connections-per-window"`
	BanDuration  time.Duration `yaml:"throttle-ban-duration"`

	CidrLenIPv4 int `yaml:"cidr-len-ipv4"`
	CidrLenIPv6 int `yaml:"cidr-len-ipv6"`

	Exempted []string

	CustomLimits map[string]CustomLimitConfig `yaml:"custom-limits"`
}

type LimiterConfig struct {
	rawLimiterConfig

	exemptedNets []flatip.IPNet
	customLimits []customLimit
}

func (config *LimiterConfig) UnmarshalYAML(unmarshal func(interface{}) error) (err error) {
	if err = unmarshal(&config.rawLimiterConfig); err != nil {
		return err
	}
	return config.postprocess()
}

func (config *LimiterConfig) postprocess() (err error) {
	exemptedNets, err := utils.ParseNetList(config.Exempted)
	if err != nil {
		return fmt.Errorf("Could not parse limiter exemption list: %v", err.Error())
	}
	config.exemptedNets = make([]flatip.IPNet, len(exemptedNets))
	for i, exempted := range exemptedNets {
		config.exemptedNets[i] = flatip.FromNetIPNet(exempted)
	}

	for identifier, customLimitConf := range config.CustomLimits {
		nets := make([]flatip.IPNet, len(customLimitConf.Nets))
		for i, netStr := range customLimitConf.Nets {
			normalizedNet, err := flatip.ParseToNormalizedNet(netStr)
			if err != nil {
				return fmt.Errorf("Bad net %s in custom-limits block %s: %w", netStr, identifier, err)
			}
			nets[i] = normalizedNet
		}
		if len(customLimitConf.Nets) == 0 {
			// see #1421: this is the legacy config format where the
			// dictionary key of the block is a CIDR string
			normalizedNet, err := flatip.ParseToNormalizedNet(identifier)
			if err != nil {
				return fmt.Errorf("Custom limit block %s has no defined nets", identifier)
			}
			nets = []flatip.IPNet{normalizedNet}
		}
		config.customLimits = append(config.customLimits, customLimit{
			maxConcurrent: customLimitConf.MaxConcurrent,
			maxPerWindow:  customLimitConf.MaxPerWindow,
			name:          md5.Sum([]byte(identifier)),
			nets:          nets,
		})
	}

	return nil
}

// Limiter manages the automated client connection limits.
type Limiter struct {
	sync.Mutex

	config *LimiterConfig

	// IP/CIDR -> count of clients connected from there:
	limiter map[limiterKey]int
	// IP/CIDR -> throttle state:
	throttler map[limiterKey]ThrottleDetails
}

// addrToKey canonicalizes `addr` to a string key, and returns
// the relevant connection limit and throttle max-per-window values
func (cl *Limiter) addrToKey(flat flatip.IP) (key limiterKey, limit int, throttle int) {
	for _, custom := range cl.config.customLimits {
		for _, net := range custom.nets {
			if net.Contains(flat) {
				return limiterKey{maskedIP: custom.name, prefixLen: 0}, custom.maxConcurrent, custom.maxPerWindow
			}
		}
	}

	var prefixLen int
	if flat.IsIPv4() {
		prefixLen = cl.config.CidrLenIPv4
		flat = flat.Mask(prefixLen, 32)
		prefixLen += 96
	} else {
		prefixLen = cl.config.CidrLenIPv6
		flat = flat.Mask(prefixLen, 128)
	}

	return limiterKey{maskedIP: flat, prefixLen: uint8(prefixLen)}, cl.config.MaxConcurrent, cl.config.MaxPerWindow
}

// AddClient adds a client to our population if possible. If we can't, throws an error instead.
func (cl *Limiter) AddClient(addr net.IP) error {
	flat := flatip.FromNetIP(addr)

	cl.Lock()
	defer cl.Unlock()

	// we don't track populations for exempted addresses or nets - this is by design
	if flatip.IPInNets(flat, cl.config.exemptedNets) {
		return nil
	}

	addrString, maxConcurrent, maxPerWindow := cl.addrToKey(flat)

	// XXX check throttle first; if we checked limit first and then checked throttle,
	// we'd have to decrement the limit on an unsuccessful throttle check
	if cl.config.Throttle {
		details := cl.throttler[addrString] // retrieve mutable throttle state from the map
		// add in constant state to process the limiting operation
		g := GenericThrottle{
			ThrottleDetails: details,
			Duration:        cl.config.Window,
			Limit:           maxPerWindow,
		}
		throttled, _ := g.Touch()                    // actually check the limit
		cl.throttler[addrString] = g.ThrottleDetails // store modified mutable state
		if throttled {
			return ErrThrottleExceeded
		}
	}

	// now check limiter
	if cl.config.Count {
		count := cl.limiter[addrString] + 1
		if count > maxConcurrent {
			return ErrLimitExceeded
		}
		cl.limiter[addrString] = count
	}

	return nil
}

// RemoveClient removes the given address from our population
func (cl *Limiter) RemoveClient(addr net.IP) {
	flat := flatip.FromNetIP(addr)

	cl.Lock()
	defer cl.Unlock()

	if !cl.config.Count || flatip.IPInNets(flat, cl.config.exemptedNets) {
		return
	}

	addrString, _, _ := cl.addrToKey(flat)
	count := cl.limiter[addrString]
	count -= 1
	if count < 0 {
		count = 0
	}
	cl.limiter[addrString] = count
}

// ResetThrottle resets the throttle count for an IP
func (cl *Limiter) ResetThrottle(addr net.IP) {
	flat := flatip.FromNetIP(addr)

	cl.Lock()
	defer cl.Unlock()

	if !cl.config.Throttle || flatip.IPInNets(flat, cl.config.exemptedNets) {
		return
	}

	addrString, _, _ := cl.addrToKey(flat)
	delete(cl.throttler, addrString)
}

// ApplyConfig atomically applies a config update to a connection limit handler
func (cl *Limiter) ApplyConfig(config *LimiterConfig) {
	cl.Lock()
	defer cl.Unlock()

	if cl.limiter == nil {
		cl.limiter = make(map[limiterKey]int)
	}
	if cl.throttler == nil {
		cl.throttler = make(map[limiterKey]ThrottleDetails)
	}

	cl.config = config
}
