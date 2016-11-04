// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import "net"
import "time"

// IPRestrictTime contains the expiration info about the given IP.
type IPRestrictTime struct {
	// Expires is when this block expires.
	Expires time.Time
	// Length is how long this block lasts for.
	Length time.Duration
}

// IsExpired returns true if the time has expired.
func (iptime *IPRestrictTime) IsExpired() bool {
	return iptime.Expires.Before(time.Now())
}

// IPBanInfo holds info about an IP/net ban.
type IPBanInfo struct {
	// Reason is the ban reason.
	Reason string
	// OperReason is an oper ban reason.
	OperReason string
	// Time holds details about the duration, if it exists.
	Time *IPRestrictTime
}

// dLineAddr contains the address itself and expiration time for a given network.
type dLineAddr struct {
	// Address is the address that is blocked.
	Address net.IP
	// Info contains information on the ban.
	Info IPBanInfo
}

// dLineNet contains the net itself and expiration time for a given network.
type dLineNet struct {
	// Network is the network that is blocked.
	Network net.IPNet
	// Info contains information on the ban.
	Info IPBanInfo
}

// DLineManager manages and dlines.
type DLineManager struct {
	// addresses that are dlined
	addresses map[string]*dLineAddr
	// networks that are dlined
	networks map[string]*dLineNet
}

// NewDLineManager returns a new DLineManager.
func NewDLineManager() *DLineManager {
	dm := DLineManager{
		addresses: make(map[string]*dLineAddr),
		networks:  make(map[string]*dLineNet),
	}
	return &dm
}

// AddNetwork adds a network to the blocked list.
func (dm *DLineManager) AddNetwork(network net.IPNet, length *IPRestrictTime) {
	netString := network.String()
	dln := dLineNet{
		Network: network,
		Info: IPBanInfo{
			Time:       length,
			Reason:     "",
			OperReason: "",
		},
	}
	dm.networks[netString] = &dln
}

// RemoveNetwork removes a network from the blocked list.
func (dm *DLineManager) RemoveNetwork(network net.IPNet) {
	netString := network.String()
	delete(dm.networks, netString)
}

// AddIP adds an IP address to the blocked list.
func (dm *DLineManager) AddIP(addr net.IP, length *IPRestrictTime) {
	addrString := addr.String()
	dla := dLineAddr{
		Address: addr,
		Info: IPBanInfo{
			Time:       length,
			Reason:     "",
			OperReason: "",
		},
	}
	dm.addresses[addrString] = &dla
}

// RemoveIP removes an IP from the blocked list.
func (dm *DLineManager) RemoveIP(addr net.IP) {
	addrString := addr.String()
	delete(dm.addresses, addrString)
}

// CheckIP returns whether or not an IP address was banned, and how long it is banned for.
func (dm *DLineManager) CheckIP(addr net.IP) (isBanned bool, info *IPBanInfo) {
	// check IP addr
	addrString := addr.String()

	addrInfo := dm.addresses[addrString]
	if addrInfo != nil {
		if addrInfo.Info.Time != nil {
			if addrInfo.Info.Time.IsExpired() {
				// ban on IP has expired, remove it from our blocked list
				dm.RemoveIP(addr)
			} else {
				return true, &addrInfo.Info
			}
		} else {
			return true, nil
		}
	}

	// check networks
	var netsToRemove []net.IPNet

	for _, netInfo := range dm.networks {
		if !netInfo.Network.Contains(addr) {
			continue
		}

		if netInfo.Info.Time != nil {
			if netInfo.Info.Time.IsExpired() {
				// ban on network has expired, remove it from our blocked list
				netsToRemove = append(netsToRemove, netInfo.Network)
			} else {
				return true, &addrInfo.Info
			}
		} else {
			return true, nil
		}
	}

	// remove expired networks
	for _, expiredNet := range netsToRemove {
		dm.RemoveNetwork(expiredNet)
	}

	// no matches!
	return false, nil
}
