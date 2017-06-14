// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/DanielOaks/girc-go/ircfmt"
	"github.com/DanielOaks/girc-go/ircmatch"
	"github.com/DanielOaks/girc-go/ircmsg"
	"github.com/oragono/oragono/irc/custime"
	"github.com/oragono/oragono/irc/sno"
	"github.com/tidwall/buntdb"
)

const (
	keyKlineEntry = "bans.kline %s"
)

// KLineInfo contains the address itself and expiration time for a given network.
type KLineInfo struct {
	// Mask that is blocked.
	Mask string
	// Matcher, to facilitate fast matching.
	Matcher ircmatch.Matcher
	// Info contains information on the ban.
	Info IPBanInfo
}

// KLineManager manages and klines.
type KLineManager struct {
	// kline'd entries
	entries map[string]*KLineInfo
}

// NewKLineManager returns a new KLineManager.
func NewKLineManager() *KLineManager {
	var km KLineManager
	km.entries = make(map[string]*KLineInfo)
	return &km
}

// AllBans returns all bans (for use with APIs, etc).
func (km *KLineManager) AllBans() map[string]IPBanInfo {
	allb := make(map[string]IPBanInfo)

	for name, info := range km.entries {
		allb[name] = info.Info
	}

	return allb
}

// AddMask adds to the blocked list.
func (km *KLineManager) AddMask(mask string, length *IPRestrictTime, reason string, operReason string) {
	kln := KLineInfo{
		Mask:    mask,
		Matcher: ircmatch.MakeMatch(mask),
		Info: IPBanInfo{
			Time:       length,
			Reason:     reason,
			OperReason: operReason,
		},
	}
	km.entries[mask] = &kln
}

// RemoveMask removes a mask from the blocked list.
func (km *KLineManager) RemoveMask(mask string) {
	delete(km.entries, mask)
}

// CheckMasks returns whether or not the hostmask(s) are banned, and how long they are banned for.
func (km *KLineManager) CheckMasks(masks ...string) (isBanned bool, info *IPBanInfo) {
	// check networks
	var masksToRemove []string

	for _, entryInfo := range km.entries {
		var matches bool
		for _, mask := range masks {
			if entryInfo.Matcher.Match(mask) {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}

		if entryInfo.Info.Time != nil {
			if entryInfo.Info.Time.IsExpired() {
				// ban on network has expired, remove it from our blocked list
				masksToRemove = append(masksToRemove, entryInfo.Mask)
			} else {
				return true, &entryInfo.Info
			}
		} else {
			return true, &entryInfo.Info
		}
	}

	// remove expired networks
	for _, expiredMask := range masksToRemove {
		km.RemoveMask(expiredMask)
	}

	// no matches!
	return false, nil
}

// KLINE [ANDKILL] [MYSELF] [duration] <mask> [ON <server>] [reason [| oper reason]]
func klineHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// check oper permissions
	if !client.class.Capabilities["oper:local_ban"] {
		client.Send(nil, server.name, ERR_NOPRIVS, client.nick, msg.Command, "Insufficient oper privs")
		return false
	}

	currentArg := 0

	// when setting a ban, if they say "ANDKILL" we should also kill all users who match it
	var andKill bool
	if len(msg.Params) > currentArg+1 && strings.ToLower(msg.Params[currentArg]) == "andkill" {
		andKill = true
		currentArg++
	}

	// when setting a ban that covers the oper's current connection, we require them to say
	// "KLINE MYSELF" so that we're sure they really mean it.
	var klineMyself bool
	if len(msg.Params) > currentArg+1 && strings.ToLower(msg.Params[currentArg]) == "myself" {
		klineMyself = true
		currentArg++
	}

	// duration
	duration, err := custime.ParseDuration(msg.Params[currentArg])
	durationIsUsed := err == nil
	if durationIsUsed {
		currentArg++
	}

	// get mask
	if len(msg.Params) < currentArg+1 {
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, msg.Command, "Not enough parameters")
		return false
	}
	mask := strings.ToLower(msg.Params[currentArg])
	currentArg++

	// check mask
	if !strings.Contains(mask, "!") && !strings.Contains(mask, "@") {
		mask = mask + "!*@*"
	} else if !strings.Contains(mask, "@") {
		mask = mask + "@*"
	}

	matcher := ircmatch.MakeMatch(mask)

	for _, clientMask := range client.AllNickmasks() {
		if !klineMyself && matcher.Match(clientMask) {
			client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, "This ban matches you. To KLINE yourself, you must use the command:  /KLINE MYSELF <arguments>")
			return false
		}
	}

	// check remote
	if len(msg.Params) > currentArg && msg.Params[currentArg] == "ON" {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, "Remote servers not yet supported")
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
		Time:       banTime,
	}

	// save in datastore
	err = server.store.Update(func(tx *buntdb.Tx) error {
		klineKey := fmt.Sprintf(keyKlineEntry, mask)

		// assemble json from ban info
		b, err := json.Marshal(info)
		if err != nil {
			return err
		}

		tx.Set(klineKey, string(b), nil)

		return nil
	})

	if err != nil {
		client.Notice(fmt.Sprintf("Could not successfully save new K-LINE: %s", err.Error()))
		return false
	}

	server.klines.AddMask(mask, banTime, reason, operReason)

	var snoDescription string
	if durationIsUsed {
		client.Notice(fmt.Sprintf("Added temporary (%s) K-Line for %s", duration.String(), mask))
		snoDescription = fmt.Sprintf(ircfmt.Unescape("%s$r added temporary (%s) K-Line for %s"), client.nick, duration.String(), mask)
	} else {
		client.Notice(fmt.Sprintf("Added K-Line for %s", mask))
		snoDescription = fmt.Sprintf(ircfmt.Unescape("%s$r added K-Line for %s"), client.nick, mask)
	}
	server.snomasks.Send(sno.LocalXline, snoDescription)

	var killClient bool
	if andKill {
		var clientsToKill []*Client
		var killedClientNicks []string

		server.clients.ByNickMutex.RLock()
		for _, mcl := range server.clients.ByNick {
			for _, clientMask := range mcl.AllNickmasks() {
				if matcher.Match(clientMask) {
					clientsToKill = append(clientsToKill, mcl)
					killedClientNicks = append(killedClientNicks, mcl.nick)
				}
			}
		}
		server.clients.ByNickMutex.RUnlock()

		for _, mcl := range clientsToKill {
			mcl.exitedSnomaskSent = true
			mcl.Quit(fmt.Sprintf("You have been banned from this server (%s)", reason))
			if mcl == client {
				killClient = true
			} else {
				// if mcl == client, we kill them below
				mcl.destroy()
			}
		}

		// send snomask
		sort.Strings(killedClientNicks)
		server.snomasks.Send(sno.LocalKills, fmt.Sprintf(ircfmt.Unescape("%s killed %d clients with a KLINE $c[grey][$r%s$c[grey]]"), client.nick, len(killedClientNicks), strings.Join(killedClientNicks, ", ")))
	}

	return killClient
}

func unKLineHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// check oper permissions
	if !client.class.Capabilities["oper:local_unban"] {
		client.Send(nil, server.name, ERR_NOPRIVS, client.nick, msg.Command, "Insufficient oper privs")
		return false
	}

	// get host
	mask := msg.Params[0]

	if !strings.Contains(mask, "!") && !strings.Contains(mask, "@") {
		mask = mask + "!*@*"
	} else if !strings.Contains(mask, "@") {
		mask = mask + "@*"
	}

	// save in datastore
	err := server.store.Update(func(tx *buntdb.Tx) error {
		klineKey := fmt.Sprintf(keyKlineEntry, mask)

		// check if it exists or not
		val, err := tx.Get(klineKey)
		if val == "" {
			return errNoExistingBan
		} else if err != nil {
			return err
		}

		tx.Delete(klineKey)
		return nil
	})

	if err != nil {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, fmt.Sprintf("Could not remove ban [%s]", err.Error()))
		return false
	}

	server.klines.RemoveMask(mask)

	client.Notice(fmt.Sprintf("Removed K-Line for %s", mask))
	server.snomasks.Send(sno.LocalXline, fmt.Sprintf(ircfmt.Unescape("%s$r removed K-Line for %s"), client.nick, mask))
	return false
}

func (s *Server) loadKLines() {
	s.klines = NewKLineManager()

	// load from datastore
	s.store.View(func(tx *buntdb.Tx) error {
		//TODO(dan): We could make this safer
		tx.AscendKeys("bans.kline *", func(key, value string) bool {
			// get address name
			key = key[len("bans.kline "):]
			mask := key

			// load ban info
			var info IPBanInfo
			json.Unmarshal([]byte(value), &info)

			// add to the server
			s.klines.AddMask(mask, info.Time, info.Reason, info.OperReason)

			return true // true to continue I guess?
		})
		return nil
	})
}
