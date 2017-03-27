// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"net"
	"time"

	"github.com/DanielOaks/girc-go/ircmsg"
)

// ThrottleDetails holds the connection-throttling details for a subnet/IP.
type ThrottleDetails struct {
	Start       time.Time
	ClientCount int
}

// ConnectionThrottle manages automated client connection throttling.
type ConnectionThrottle struct {
	enabled     bool
	ipv4Mask    net.IPMask
	ipv6Mask    net.IPMask
	subnetLimit int
	duration    time.Duration
	population  map[string]ThrottleDetails

	// used by the server to ban clients that go over this limit
	BanDuration     time.Duration
	BanMessage      string
	BanMessageBytes []byte

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

// NewConnectionThrottle returns a new client connection throttler.
func NewConnectionThrottle(config ConnectionThrottleConfig) (*ConnectionThrottle, error) {
	var ct ConnectionThrottle
	ct.enabled = config.Enabled

	ct.population = make(map[string]ThrottleDetails)
	ct.exemptedIPs = make(map[string]bool)

	ct.ipv4Mask = net.CIDRMask(config.CidrLenIPv4, 32)
	ct.ipv6Mask = net.CIDRMask(config.CidrLenIPv6, 128)
	ct.subnetLimit = config.ConnectionsPerCidr

	ct.duration = config.Duration

	ct.BanDuration = config.BanDuration
	ct.BanMessage = config.BanMessage
	ircmsgOutput := ircmsg.MakeMessage(nil, "", "ERROR", ct.BanMessage)
	msg, err := ircmsgOutput.Line()
	if err != nil {
		return nil, fmt.Errorf("Could not make error message: %s", err.Error())
	}
	ct.BanMessageBytes = []byte(msg)

	// assemble exempted nets
	for _, cidr := range config.Exempted {
		ipaddr := net.ParseIP(cidr)
		_, netaddr, err := net.ParseCIDR(cidr)

		if ipaddr == nil && err != nil {
			return nil, fmt.Errorf("Could not parse exempted IP/network [%s]", cidr)
		}

		if ipaddr != nil {
			ct.exemptedIPs[ipaddr.String()] = true
		} else {
			ct.exemptedNets = append(ct.exemptedNets, *netaddr)
		}
	}

	return &ct, nil
}
