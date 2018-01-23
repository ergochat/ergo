// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/goshuirc/irc-go/ircmatch"
	"github.com/goshuirc/irc-go/ircmsg"
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
	sync.RWMutex // tier 1
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

	km.RLock()
	defer km.RUnlock()
	for name, info := range km.entries {
		allb[name] = info.Info
	}

	return allb
}

// AddMask adds to the blocked list.
func (km *KLineManager) AddMask(mask string, length *IPRestrictTime, reason, operReason, operName string) {
	kln := KLineInfo{
		Mask:    mask,
		Matcher: ircmatch.MakeMatch(mask),
		Info: IPBanInfo{
			Time:       length,
			Reason:     reason,
			OperReason: operReason,
			OperName:   operName,
		},
	}
	km.Lock()
	km.entries[mask] = &kln
	km.Unlock()
}

// RemoveMask removes a mask from the blocked list.
func (km *KLineManager) RemoveMask(mask string) {
	km.Lock()
	delete(km.entries, mask)
	km.Unlock()
}

// CheckMasks returns whether or not the hostmask(s) are banned, and how long they are banned for.
func (km *KLineManager) CheckMasks(masks ...string) (isBanned bool, info *IPBanInfo) {
	doCleanup := false
	defer func() {
		// asynchronously remove expired bans
		if doCleanup {
			go func() {
				km.Lock()
				defer km.Unlock()
				for key, entry := range km.entries {
					if entry.Info.Time.IsExpired() {
						delete(km.entries, key)
					}
				}
			}()
		}
	}()

	km.RLock()
	defer km.RUnlock()

	for _, entryInfo := range km.entries {
		if entryInfo.Info.Time != nil && entryInfo.Info.Time.IsExpired() {
			doCleanup = true
			continue
		}

		matches := false
		for _, mask := range masks {
			if entryInfo.Matcher.Match(mask) {
				matches = true
				break
			}
		}
		if matches {
			return true, &entryInfo.Info
		}
	}

	// no matches!
	return false, nil
}

// KLINE [ANDKILL] [MYSELF] [duration] <mask> [ON <server>] [reason [| oper reason]]
// KLINE LIST
func klineHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// check oper permissions
	if !client.class.Capabilities["oper:local_ban"] {
		client.Send(nil, server.name, ERR_NOPRIVS, client.nick, msg.Command, client.t("Insufficient oper privs"))
		return false
	}

	currentArg := 0

	// if they say LIST, we just list the current klines
	if len(msg.Params) == currentArg+1 && strings.ToLower(msg.Params[currentArg]) == "list" {
		bans := server.klines.AllBans()

		if len(bans) == 0 {
			client.Notice("No KLINEs have been set!")
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
		client.Send(nil, server.name, ERR_NEEDMOREPARAMS, client.nick, msg.Command, client.t("Not enough parameters"))
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
			client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("This ban matches you. To KLINE yourself, you must use the command:  /KLINE MYSELF <arguments>"))
			return false
		}
	}

	// check remote
	if len(msg.Params) > currentArg && msg.Params[currentArg] == "ON" {
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, client.t("Remote servers not yet supported"))
		return false
	}

	// get oper name
	operName := client.operName
	if operName == "" {
		operName = server.name
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
		OperName:   operName,
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
		client.Notice(fmt.Sprintf(client.t("Could not successfully save new K-LINE: %s"), err.Error()))
		return false
	}

	server.klines.AddMask(mask, banTime, reason, operReason, operName)

	var snoDescription string
	if durationIsUsed {
		client.Notice(fmt.Sprintf(client.t("Added temporary (%[1]s) K-Line for %[2]s"), duration.String(), mask))
		snoDescription = fmt.Sprintf(ircfmt.Unescape("%s [%s]$r added temporary (%s) K-Line for %s"), client.nick, operName, duration.String(), mask)
	} else {
		client.Notice(fmt.Sprintf(client.t("Added K-Line for %s"), mask))
		snoDescription = fmt.Sprintf(ircfmt.Unescape("%s [%s]$r added K-Line for %s"), client.nick, operName, mask)
	}
	server.snomasks.Send(sno.LocalXline, snoDescription)

	var killClient bool
	if andKill {
		var clientsToKill []*Client
		var killedClientNicks []string

		for _, mcl := range server.clients.AllClients() {
			for _, clientMask := range mcl.AllNickmasks() {
				if matcher.Match(clientMask) {
					clientsToKill = append(clientsToKill, mcl)
					killedClientNicks = append(killedClientNicks, mcl.nick)
				}
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
		server.snomasks.Send(sno.LocalKills, fmt.Sprintf(ircfmt.Unescape("%s [%s] killed %d clients with a KLINE $c[grey][$r%s$c[grey]]"), client.nick, operName, len(killedClientNicks), strings.Join(killedClientNicks, ", ")))
	}

	return killClient
}

func unKLineHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// check oper permissions
	if !client.class.Capabilities["oper:local_unban"] {
		client.Send(nil, server.name, ERR_NOPRIVS, client.nick, msg.Command, client.t("Insufficient oper privs"))
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
		client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, msg.Command, fmt.Sprintf(client.t("Could not remove ban [%s]"), err.Error()))
		return false
	}

	server.klines.RemoveMask(mask)

	client.Notice(fmt.Sprintf(client.t("Removed K-Line for %s"), mask))
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

			// add oper name if it doesn't exist already
			if info.OperName == "" {
				info.OperName = s.name
			}

			// add to the server
			s.klines.AddMask(mask, info.Time, info.Reason, info.OperReason, info.OperName)

			return true // true to continue I guess?
		})
		return nil
	})
}
