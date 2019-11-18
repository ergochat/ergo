// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package connection_limits

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/oragono/oragono/irc/utils"
)

var (
	ErrLimitExceeded    = errors.New("too many concurrent connections")
	ErrThrottleExceeded = errors.New("too many recent connection attempts")
)

type CustomLimitConfig struct {
	MaxConcurrent int `yaml:"max-concurrent-connections"`
	MaxPerWindow  int `yaml:"max-connections-per-window"`
}

// tuples the key-value pair of a CIDR and its custom limit/throttle values
type customLimit struct {
	CustomLimitConfig
	ipNet net.IPNet
}

// LimiterConfig controls the automated connection limits.
// RawLimiterConfig contains all the YAML-visible fields;
// LimiterConfig contains additional denormalized private fields
type RawLimiterConfig struct {
	Limit         bool
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
	RawLimiterConfig

	ipv4Mask     net.IPMask
	ipv6Mask     net.IPMask
	exemptedNets []net.IPNet
	customLimits []customLimit
}

func (config *LimiterConfig) UnmarshalYAML(unmarshal func(interface{}) error) (err error) {
	if err = unmarshal(&config.RawLimiterConfig); err != nil {
		return err
	}
	return config.postprocess()
}

func (config *LimiterConfig) postprocess() (err error) {
	config.exemptedNets, err = utils.ParseNetList(config.Exempted)
	if err != nil {
		return fmt.Errorf("Could not parse limiter exemption list: %v", err.Error())
	}

	for netStr, customLimitConf := range config.CustomLimits {
		normalizedNet, err := utils.NormalizedNetFromString(netStr)
		if err != nil {
			return fmt.Errorf("Could not parse custom limit specification: %v", err.Error())
		}
		config.customLimits = append(config.customLimits, customLimit{
			CustomLimitConfig: customLimitConf,
			ipNet:             normalizedNet,
		})
	}

	config.ipv4Mask = net.CIDRMask(config.CidrLenIPv4, 32)
	config.ipv6Mask = net.CIDRMask(config.CidrLenIPv6, 128)

	return nil
}

// Limiter manages the automated client connection limits.
type Limiter struct {
	sync.Mutex

	config *LimiterConfig

	// IP/CIDR -> count of clients connected from there:
	limiter map[string]int
	// IP/CIDR -> throttle state:
	throttler map[string]ThrottleDetails
}

// addrToKey canonicalizes `addr` to a string key, and returns
// the relevant connection limit and throttle max-per-window values
func (cl *Limiter) addrToKey(addr net.IP) (key string, limit int, throttle int) {
	// `key` will be a CIDR string like "8.8.8.8/32" or "2001:0db8::/32"
	for _, custom := range cl.config.customLimits {
		if custom.ipNet.Contains(addr) {
			return custom.ipNet.String(), custom.MaxConcurrent, custom.MaxPerWindow
		}
	}

	var ipNet net.IPNet
	addrv4 := addr.To4()
	if addrv4 != nil {
		ipNet = net.IPNet{
			IP:   addrv4.Mask(cl.config.ipv4Mask),
			Mask: cl.config.ipv4Mask,
		}
	} else {
		ipNet = net.IPNet{
			IP:   addr.Mask(cl.config.ipv6Mask),
			Mask: cl.config.ipv6Mask,
		}
	}
	return ipNet.String(), cl.config.MaxConcurrent, cl.config.MaxPerWindow
}

// AddClient adds a client to our population if possible. If we can't, throws an error instead.
func (cl *Limiter) AddClient(addr net.IP) error {
	cl.Lock()
	defer cl.Unlock()

	// we don't track populations for exempted addresses or nets - this is by design
	if utils.IPInNets(addr, cl.config.exemptedNets) {
		return nil
	}

	addrString, maxConcurrent, maxPerWindow := cl.addrToKey(addr)

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
	if cl.config.Limit {
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
	cl.Lock()
	defer cl.Unlock()

	if !cl.config.Limit || utils.IPInNets(addr, cl.config.exemptedNets) {
		return
	}

	addrString, _, _ := cl.addrToKey(addr)
	count := cl.limiter[addrString]
	count -= 1
	if count < 0 {
		count = 0
	}
	cl.limiter[addrString] = count
}

// ResetThrottle resets the throttle count for an IP
func (cl *Limiter) ResetThrottle(addr net.IP) {
	cl.Lock()
	defer cl.Unlock()

	if !cl.config.Throttle || utils.IPInNets(addr, cl.config.exemptedNets) {
		return
	}

	addrString, _, _ := cl.addrToKey(addr)
	delete(cl.throttler, addrString)
}

// ApplyConfig atomically applies a config update to a connection limit handler
func (cl *Limiter) ApplyConfig(config *LimiterConfig) {
	cl.Lock()
	defer cl.Unlock()

	if cl.limiter == nil {
		cl.limiter = make(map[string]int)
	}
	if cl.throttler == nil {
		cl.throttler = make(map[string]ThrottleDetails)
	}

	cl.config = config
}
