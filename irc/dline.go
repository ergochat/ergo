// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"strings"

	"encoding/json"

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/oragono/oragono/irc/custime"
	"github.com/oragono/oragono/irc/sno"
	"github.com/tidwall/buntdb"
)

const (
	keyDlineEntry = "bans.dline %s"
)

var (
	errNoExistingBan = errors.New("Ban does not exist")
)

// IPRestrictTime contains the expiration info about the given IP.
type IPRestrictTime struct {
	// Duration is how long this block lasts for.
	Duration time.Duration `json:"duration"`
	// Expires is when this block expires.
	Expires time.Time `json:"expires"`
}

// IsExpired returns true if the time has expired.
func (iptime *IPRestrictTime) IsExpired() bool {
	return iptime.Expires.Before(time.Now())
}

// IPBanInfo holds info about an IP/net ban.
type IPBanInfo struct {
	// Reason is the ban reason.
	Reason string `json:"reason"`
	// OperReason is an oper ban reason.
	OperReason string `json:"oper_reason"`
	// OperName is the oper who set the ban.
	OperName string `json:"oper_name"`
	// Time holds details about the duration, if it exists.
	Time *IPRestrictTime `json:"time"`
}

// BanMessage returns the ban message.
func (info IPBanInfo) BanMessage(message string) string {
	message = fmt.Sprintf(message, info.Reason)
	if info.Time != nil {
		message += fmt.Sprintf(" [%s]", info.Time.Duration.String())
	}
	return message
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
	sync.RWMutex // tier 1
	// addresses that are dlined
	addresses map[string]*dLineAddr
	// networks that are dlined
	networks map[string]*dLineNet
}

// NewDLineManager returns a new DLineManager.
func NewDLineManager() *DLineManager {
	var dm DLineManager
	dm.addresses = make(map[string]*dLineAddr)
	dm.networks = make(map[string]*dLineNet)
	return &dm
}

// AllBans returns all bans (for use with APIs, etc).
func (dm *DLineManager) AllBans() map[string]IPBanInfo {
	allb := make(map[string]IPBanInfo)

	dm.RLock()
	defer dm.RUnlock()

	for name, info := range dm.addresses {
		allb[name] = info.Info
	}
	for name, info := range dm.networks {
		allb[name] = info.Info
	}

	return allb
}

// AddNetwork adds a network to the blocked list.
func (dm *DLineManager) AddNetwork(network net.IPNet, length *IPRestrictTime, reason, operReason, operName string) {
	netString := network.String()
	dln := dLineNet{
		Network: network,
		Info: IPBanInfo{
			Time:       length,
			Reason:     reason,
			OperReason: operReason,
			OperName:   operName,
		},
	}
	dm.Lock()
	dm.networks[netString] = &dln
	dm.Unlock()
}

// RemoveNetwork removes a network from the blocked list.
func (dm *DLineManager) RemoveNetwork(network net.IPNet) {
	netString := network.String()
	dm.Lock()
	delete(dm.networks, netString)
	dm.Unlock()
}

// AddIP adds an IP address to the blocked list.
func (dm *DLineManager) AddIP(addr net.IP, length *IPRestrictTime, reason, operReason, operName string) {
	addrString := addr.String()
	dla := dLineAddr{
		Address: addr,
		Info: IPBanInfo{
			Time:       length,
			Reason:     reason,
			OperReason: operReason,
			OperName:   operName,
		},
	}
	dm.Lock()
	dm.addresses[addrString] = &dla
	dm.Unlock()
}

// RemoveIP removes an IP from the blocked list.
func (dm *DLineManager) RemoveIP(addr net.IP) {
	addrString := addr.String()
	dm.Lock()
	delete(dm.addresses, addrString)
	dm.Unlock()
}

// CheckIP returns whether or not an IP address was banned, and how long it is banned for.
func (dm *DLineManager) CheckIP(addr net.IP) (isBanned bool, info *IPBanInfo) {
	// check IP addr
	addrString := addr.String()
	dm.RLock()
	addrInfo := dm.addresses[addrString]
	dm.RUnlock()

	if addrInfo != nil {
		if addrInfo.Info.Time != nil {
			if addrInfo.Info.Time.IsExpired() {
				// ban on IP has expired, remove it from our blocked list
				dm.RemoveIP(addr)
			} else {
				return true, &addrInfo.Info
			}
		} else {
			return true, &addrInfo.Info
		}
	}

	// check networks
	doCleanup := false
	defer func() {
		if doCleanup {
			go func() {
				dm.Lock()
				defer dm.Unlock()
				for key, netInfo := range dm.networks {
					if netInfo.Info.Time.IsExpired() {
						delete(dm.networks, key)
					}
				}
			}()
		}
	}()

	dm.RLock()
	defer dm.RUnlock()

	for _, netInfo := range dm.networks {
		if netInfo.Info.Time != nil && netInfo.Info.Time.IsExpired() {
			// expired ban, ignore and clean up later
			doCleanup = true
		} else if netInfo.Network.Contains(addr) {
			return true, &netInfo.Info
		}
	}
	// no matches!
	return false, nil
}

// DLINE [ANDKILL] [MYSELF] [duration] <ip>/<net> [ON <server>] [reason [| oper reason]]
// DLINE LIST
func dlineHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// check oper permissions
	if !client.class.Capabilities["oper:local_ban"] {
		client.Send(nil, server.name, ERR_NOPRIVS, client.nick, msg.Command, client.t("Insufficient oper privs"))
		return false
	}

	currentArg := 0

	// if they say LIST, we just list the current dlines
	if len(msg.Params) == currentArg+1 && strings.ToLower(msg.Params[currentArg]) == "list" {
		bans := server.dlines.AllBans()

		if len(bans) == 0 {
			client.Notice(client.t("No DLINEs have been set!"))
		}

		for key, info := range bans {
			client.Notice(fmt.Sprintf(client.t("Ban - %s - added by %s - %s"), key, info.OperName, info.BanMessage("%s")))
		}

		return false
	}

	// when setting a ban, if they say "ANDKILL" we should also kill all users who match it
	var andKill bool
	if len(msg.Params) > currentArg+1 && strings.ToLower(msg.Params[currentArg]) == "andkill" {
		andKill = true
		currentArg++
	}

	// when setting a ban that covers the oper's current connection, we require them to say
	// "DLINE MYSELF" so that we're sure they really mean it.
	var dlineMyself bool
	if len(msg.Params) > currentArg+1 && strings.ToLower(msg.Params[currentArg]) == "myself" {
		dlineMyself = true
		currentArg++
	}

	// duration
	duration, err := custime.ParseDuration(msg.Params[currentArg])
	durationIsUsed := err == nil
	if durationIsUsed {
		currentArg++
	}

	// get host
	if len(msg.Params) < currentArg+1 {
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, msg.Command, client.t("Not enough parameters"))
		return false
	}
	hostString := msg.Params[currentArg]
	currentArg++

	// check host
	var hostAddr net.IP
	var hostNet *net.IPNet

	_, hostNet, err = net.ParseCIDR(hostString)
	if err != nil {
		hostAddr = net.ParseIP(hostString)
	}

	if hostAddr == nil && hostNet == nil {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("Could not parse IP address or CIDR network"))
		return false
	}

	if hostNet == nil {
		hostString = hostAddr.String()
		if !dlineMyself && hostAddr.Equal(client.IP()) {
			client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("This ban matches you. To DLINE yourself, you must use the command:  /DLINE MYSELF <arguments>"))
			return false
		}
	} else {
		hostString = hostNet.String()
		if !dlineMyself && hostNet.Contains(client.IP()) {
			client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("This ban matches you. To DLINE yourself, you must use the command:  /DLINE MYSELF <arguments>"))
			return false
		}
	}

	// check remote
	if len(msg.Params) > currentArg && msg.Params[currentArg] == "ON" {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("Remote servers not yet supported"))
		return false
	}

	// get comment(s)
	reason := "No reason given"
	operReason := "No reason given"
	if len(msg.Params) > currentArg {
		tempReason := strings.TrimSpace(msg.Params[currentArg])
		if len(tempReason) > 0 && tempReason != "|" {
			tempReasons := strings.SplitN(tempReason, "|", 2)
			if tempReasons[0] != "" {
				reason = tempReasons[0]
			}
			if len(tempReasons) > 1 && tempReasons[1] != "" {
				operReason = tempReasons[1]
			} else {
				operReason = reason
			}
		}
	}
	operName := client.operName
	if operName == "" {
		operName = server.name
	}

	// assemble ban info
	var banTime *IPRestrictTime
	if durationIsUsed {
		banTime = &IPRestrictTime{
			Duration: duration,
			Expires:  time.Now().Add(duration),
		}
	}

	info := IPBanInfo{
		Reason:     reason,
		OperReason: operReason,
		OperName:   operName,
		Time:       banTime,
	}

	// save in datastore
	err = server.store.Update(func(tx *buntdb.Tx) error {
		dlineKey := fmt.Sprintf(keyDlineEntry, hostString)

		// assemble json from ban info
		b, err := json.Marshal(info)
		if err != nil {
			return err
		}

		tx.Set(dlineKey, string(b), nil)

		return nil
	})

	if err != nil {
		client.Notice(fmt.Sprintf(client.t("Could not successfully save new D-LINE: %s"), err.Error()))
		return false
	}

	if hostNet == nil {
		server.dlines.AddIP(hostAddr, banTime, reason, operReason, operName)
	} else {
		server.dlines.AddNetwork(*hostNet, banTime, reason, operReason, operName)
	}

	var snoDescription string
	if durationIsUsed {
		client.Notice(fmt.Sprintf("Added temporary (%s) D-Line for %s", duration.String(), hostString))
		snoDescription = fmt.Sprintf(ircfmt.Unescape("%s [%s]$r added temporary (%s) D-Line for %s"), client.nick, operName, duration.String(), hostString)
	} else {
		client.Notice(fmt.Sprintf("Added D-Line for %s", hostString))
		snoDescription = fmt.Sprintf(ircfmt.Unescape("%s [%s]$r added D-Line for %s"), client.nick, operName, hostString)
	}
	server.snomasks.Send(sno.LocalXline, snoDescription)

	var killClient bool
	if andKill {
		var clientsToKill []*Client
		var killedClientNicks []string
		var toKill bool

		for _, mcl := range server.clients.AllClients() {
			if hostNet == nil {
				toKill = hostAddr.Equal(mcl.IP())
			} else {
				toKill = hostNet.Contains(mcl.IP())
			}

			if toKill {
				clientsToKill = append(clientsToKill, mcl)
				killedClientNicks = append(killedClientNicks, mcl.nick)
			}
		}

		for _, mcl := range clientsToKill {
			mcl.exitedSnomaskSent = true
			mcl.Quit(fmt.Sprintf(mcl.t("You have been banned from this server (%s)"), reason))
			if mcl == client {
				killClient = true
			} else {
				// if mcl == client, we kill them below
				mcl.destroy(false)
			}
		}

		// send snomask
		sort.Strings(killedClientNicks)
		server.snomasks.Send(sno.LocalKills, fmt.Sprintf(ircfmt.Unescape("%s [%s] killed %d clients with a DLINE $c[grey][$r%s$c[grey]]"), client.nick, operName, len(killedClientNicks), strings.Join(killedClientNicks, ", ")))
	}

	return killClient
}

func unDLineHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// check oper permissions
	if !client.class.Capabilities["oper:local_unban"] {
		client.Send(nil, server.name, ERR_NOPRIVS, client.nick, msg.Command, client.t("Insufficient oper privs"))
		return false
	}

	// get host
	hostString := msg.Params[0]

	// check host
	var hostAddr net.IP
	var hostNet *net.IPNet

	_, hostNet, err := net.ParseCIDR(hostString)
	if err != nil {
		hostAddr = net.ParseIP(hostString)
	}

	if hostAddr == nil && hostNet == nil {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("Could not parse IP address or CIDR network"))
		return false
	}

	if hostNet == nil {
		hostString = hostAddr.String()
	} else {
		hostString = hostNet.String()
	}

	// save in datastore
	err = server.store.Update(func(tx *buntdb.Tx) error {
		dlineKey := fmt.Sprintf(keyDlineEntry, hostString)

		// check if it exists or not
		val, err := tx.Get(dlineKey)
		if val == "" {
			return errNoExistingBan
		} else if err != nil {
			return err
		}

		tx.Delete(dlineKey)
		return nil
	})

	if err != nil {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, fmt.Sprintf(client.t("Could not remove ban [%s]"), err.Error()))
		return false
	}

	if hostNet == nil {
		server.dlines.RemoveIP(hostAddr)
	} else {
		server.dlines.RemoveNetwork(*hostNet)
	}

	client.Notice(fmt.Sprintf(client.t("Removed D-Line for %s"), hostString))
	server.snomasks.Send(sno.LocalXline, fmt.Sprintf(ircfmt.Unescape("%s$r removed D-Line for %s"), client.nick, hostString))
	return false
}

func (s *Server) loadDLines() {
	s.dlines = NewDLineManager()

	// load from datastore
	s.store.View(func(tx *buntdb.Tx) error {
		//TODO(dan): We could make this safer
		tx.AscendKeys("bans.dline *", func(key, value string) bool {
			// get address name
			key = key[len("bans.dline "):]

			// load addr/net
			var hostAddr net.IP
			var hostNet *net.IPNet
			_, hostNet, err := net.ParseCIDR(key)
			if err != nil {
				hostAddr = net.ParseIP(key)
			}

			// load ban info
			var info IPBanInfo
			json.Unmarshal([]byte(value), &info)

			// set opername if it isn't already set
			if info.OperName == "" {
				info.OperName = s.name
			}

			// add to the server
			if hostNet == nil {
				s.dlines.AddIP(hostAddr, info.Time, info.Reason, info.OperReason, info.OperName)
			} else {
				s.dlines.AddNetwork(*hostNet, info.Time, info.Reason, info.OperReason, info.OperName)
			}

			return true // true to continue I guess?
		})
		return nil
	})
}
