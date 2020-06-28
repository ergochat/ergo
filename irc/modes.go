// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/sno"
)

var (
	// DefaultChannelModes are enabled on brand new channels when they're created.
	// this can be overridden in the `channels` config, with the `default-modes` key
	DefaultChannelModes = modes.Modes{
		modes.NoOutside, modes.OpOnlyTopic,
	}

	// DefaultUserModes are set on all users when they login.
	// this can be overridden in the `accounts` config, with the `default-user-modes` key
	DefaultUserModes = modes.Modes{}
)

// ApplyUserModeChanges applies the given changes, and returns the applied changes.
// `oper` is the operclass of the client gaining +o, when applicable (this is just
// to confirm that the client actually has a valid operclass)
func ApplyUserModeChanges(client *Client, changes modes.ModeChanges, force bool, oper *Oper) modes.ModeChanges {
	applied := make(modes.ModeChanges, 0)

	for _, change := range changes {
		switch change.Mode {
		case modes.Bot, modes.Invisible, modes.WallOps, modes.UserRoleplaying, modes.Operator, modes.LocalOperator, modes.RegisteredOnly, modes.UserNoCTCP:
			switch change.Op {
			case modes.Add:
				if (change.Mode == modes.Operator || change.Mode == modes.LocalOperator) && !(force && oper != nil) {
					continue
				}

				if client.SetMode(change.Mode, true) {
					if change.Mode == modes.Invisible {
						client.server.stats.ChangeInvisible(1)
					} else if change.Mode == modes.Operator || change.Mode == modes.LocalOperator {
						client.server.stats.ChangeOperators(1)
					}
					applied = append(applied, change)
				}

			case modes.Remove:
				var removedSnomasks string
				if client.SetMode(change.Mode, false) {
					if change.Mode == modes.Invisible {
						client.server.stats.ChangeInvisible(-1)
					} else if change.Mode == modes.Operator || change.Mode == modes.LocalOperator {
						removedSnomasks = client.server.snomasks.String(client)
						client.server.stats.ChangeOperators(-1)
						applyOper(client, nil, nil)
						if removedSnomasks != "" {
							client.server.snomasks.RemoveClient(client)
						}
					}
					applied = append(applied, change)
					if removedSnomasks != "" {
						applied = append(applied, modes.ModeChange{
							Mode: modes.ServerNotice,
							Op:   modes.Remove,
							Arg:  removedSnomasks,
						})
					}
				}
			}

		case modes.ServerNotice:
			if !client.HasMode(modes.Operator) {
				continue
			}
			var masks []sno.Mask
			if change.Op == modes.Add || change.Op == modes.Remove {
				var newArg string
				for _, char := range change.Arg {
					mask := sno.Mask(char)
					if sno.ValidMasks[mask] {
						masks = append(masks, mask)
						newArg += string(char)
					}
				}
				change.Arg = newArg
			}
			if change.Op == modes.Add {
				client.server.snomasks.AddMasks(client, masks...)
				applied = append(applied, change)
			} else if change.Op == modes.Remove {
				client.server.snomasks.RemoveMasks(client, masks...)
				applied = append(applied, change)
			}
		}

		// can't do anything to TLS mode
	}

	if len(applied) != 0 {
		client.markDirty(IncludeUserModes)
	}

	// return the changes we could actually apply
	return applied
}

// parseDefaultModes uses the provided mode change parser to parse the rawModes.
func parseDefaultModes(rawModes string, parser func(params ...string) (modes.ModeChanges, map[rune]bool)) modes.Modes {
	modeChangeStrings := strings.Fields(rawModes)
	modeChanges, _ := parser(modeChangeStrings...)
	defaultModes := make(modes.Modes, 0)
	for _, modeChange := range modeChanges {
		if modeChange.Op == modes.Add {
			defaultModes = append(defaultModes, modeChange.Mode)
		}
	}
	return defaultModes
}

// ParseDefaultChannelModes parses the `default-modes` line of the config
func ParseDefaultChannelModes(rawModes *string) modes.Modes {
	if rawModes == nil {
		// not present in config, fall back to compile-time default
		return DefaultChannelModes
	}
	return parseDefaultModes(*rawModes, modes.ParseChannelModeChanges)
}

// ParseDefaultUserModes parses the `default-user-modes` line of the config
func ParseDefaultUserModes(rawModes *string) modes.Modes {
	if rawModes == nil {
		// not present in config, fall back to compile-time default
		return DefaultUserModes
	}
	return parseDefaultModes(*rawModes, modes.ParseUserModeChanges)
}

// #1021: channel key must be valid as a non-final parameter
func validateChannelKey(key string) bool {
	// empty string is valid in this context because it unsets the mode
	if len(key) == 0 {
		return true
	}
	return key[0] != ':' && strings.IndexByte(key, ' ') == -1
}

// ApplyChannelModeChanges applies a given set of mode changes.
func (channel *Channel) ApplyChannelModeChanges(client *Client, isSamode bool, changes modes.ModeChanges, rb *ResponseBuffer) (applied modes.ModeChanges) {
	// so we only output one warning for each list type when full
	listFullWarned := make(map[modes.Mode]bool)

	var alreadySentPrivError bool

	maskOpCount := 0
	chname := channel.Name()
	details := client.Details()

	hasPrivs := func(change modes.ModeChange) bool {
		if isSamode {
			return true
		}
		if details.account != "" && details.account == channel.Founder() {
			return true
		}
		switch change.Mode {
		case modes.ChannelFounder, modes.ChannelAdmin, modes.ChannelOperator, modes.Halfop, modes.Voice:
			// List on these modes is a no-op anyway
			if change.Op == modes.List {
				return true
			}
			cfarg, _ := CasefoldName(change.Arg)
			isSelfChange := cfarg == details.nickCasefolded
			if change.Op == modes.Remove && isSelfChange {
				// "There is no restriction, however, on anyone `deopping' themselves"
				// <https://tools.ietf.org/html/rfc2812#section-3.1.5>
				return true
			}
			return channelUserModeHasPrivsOver(channel.HighestUserMode(client), change.Mode)
		case modes.InviteMask, modes.ExceptMask:
			// listing these requires privileges
			return channel.ClientIsAtLeast(client, modes.ChannelOperator)
		default:
			// #163: allow unprivileged users to list ban masks, and any other modes
			return change.Op == modes.List || channel.ClientIsAtLeast(client, modes.ChannelOperator)
		}
	}

	for _, change := range changes {
		if !hasPrivs(change) {
			if !alreadySentPrivError {
				alreadySentPrivError = true
				rb.Add(nil, client.server.name, ERR_CHANOPRIVSNEEDED, details.nick, channel.name, client.t("You're not a channel operator"))
			}
			continue
		}

		switch change.Mode {
		case modes.BanMask, modes.ExceptMask, modes.InviteMask:
			maskOpCount += 1
			if change.Op == modes.List {
				channel.ShowMaskList(client, change.Mode, rb)
				continue
			}

			mask := change.Arg
			switch change.Op {
			case modes.Add:
				if channel.lists[change.Mode].Length() >= client.server.Config().Limits.ChanListModes {
					if !listFullWarned[change.Mode] {
						rb.Add(nil, client.server.name, ERR_BANLISTFULL, details.nick, chname, change.Mode.String(), client.t("Channel list is full"))
						listFullWarned[change.Mode] = true
					}
					continue
				}

				maskAdded, err := channel.lists[change.Mode].Add(mask, details.nickMask, details.accountName)
				if maskAdded != "" {
					appliedChange := change
					appliedChange.Arg = maskAdded
					applied = append(applied, appliedChange)
				} else if err != nil {
					rb.Add(nil, client.server.name, ERR_INVALIDMODEPARAM, details.nick, mask, fmt.Sprintf(client.t("Invalid mode %[1]s parameter: %[2]s"), string(change.Mode), mask))
				} else {
					rb.Add(nil, client.server.name, ERR_LISTMODEALREADYSET, chname, mask, string(change.Mode), fmt.Sprintf(client.t("Channel %[1]s list already contains %[2]s"), chname, mask))
				}

			case modes.Remove:
				maskRemoved, err := channel.lists[change.Mode].Remove(mask)
				if maskRemoved != "" {
					appliedChange := change
					appliedChange.Arg = maskRemoved
					applied = append(applied, appliedChange)
				} else if err != nil {
					rb.Add(nil, client.server.name, ERR_INVALIDMODEPARAM, details.nick, mask, fmt.Sprintf(client.t("Invalid mode %[1]s parameter: %[2]s"), string(change.Mode), mask))
				} else {
					rb.Add(nil, client.server.name, ERR_LISTMODENOTSET, chname, mask, string(change.Mode), fmt.Sprintf(client.t("Channel %[1]s list does not contain %[2]s"), chname, mask))
				}
			}

		case modes.UserLimit:
			switch change.Op {
			case modes.Add:
				val, err := strconv.Atoi(change.Arg)
				if err == nil {
					channel.setUserLimit(val)
					applied = append(applied, change)
				}

			case modes.Remove:
				channel.setUserLimit(0)
				applied = append(applied, change)
			}

		case modes.Key:
			switch change.Op {
			case modes.Add:
				if validateChannelKey(change.Arg) {
					channel.setKey(change.Arg)
					applied = append(applied, change)
				} else {
					rb.Add(nil, client.server.name, ERR_INVALIDMODEPARAM, details.nick, "*", fmt.Sprintf(client.t("Invalid mode %[1]s parameter: %[2]s"), string(change.Mode), change.Arg))
				}
			case modes.Remove:
				channel.setKey("")
				applied = append(applied, change)
			}

		case modes.InviteOnly, modes.Moderated, modes.NoOutside, modes.OpOnlyTopic, modes.RegisteredOnly, modes.Secret, modes.ChanRoleplaying, modes.NoCTCP:
			if change.Op == modes.List {
				continue
			}

			if channel.flags.SetMode(change.Mode, change.Op == modes.Add) {
				applied = append(applied, change)
			}

		case modes.ChannelFounder, modes.ChannelAdmin, modes.ChannelOperator, modes.Halfop, modes.Voice:
			if change.Op == modes.List {
				continue
			}

			nick := change.Arg
			if nick == "" {
				rb.Add(nil, client.server.name, ERR_NEEDMOREPARAMS, client.Nick(), "MODE", client.t("Not enough parameters"))
				continue
			}

			success, change := channel.applyModeToMember(client, change, rb)
			if success {
				applied = append(applied, change)
			}
		}
	}

	var includeFlags uint
	for _, change := range applied {
		switch change.Mode {
		case modes.BanMask, modes.ExceptMask, modes.InviteMask:
			includeFlags |= IncludeLists
		case modes.ChannelFounder, modes.ChannelAdmin, modes.ChannelOperator, modes.Halfop, modes.Voice:
			// these are never persisted currently, but might be in the future (see discussion on #729)
		default:
			includeFlags |= IncludeModes
		}
	}
	if includeFlags != 0 {
		channel.MarkDirty(includeFlags)
	}

	// #649: don't send 324 RPL_CHANNELMODEIS if we were only working with mask lists
	if len(applied) == 0 && !alreadySentPrivError && (maskOpCount == 0 || maskOpCount < len(changes)) {
		args := append([]string{details.nick, chname}, channel.modeStrings(client)...)
		rb.Add(nil, client.server.name, RPL_CHANNELMODEIS, args...)
		rb.Add(nil, client.server.name, RPL_CREATIONTIME, details.nick, chname, strconv.FormatInt(channel.createdTime.Unix(), 10))
	}

	return applied
}

// tests whether l > r, in the channel-user mode ordering (e.g., Halfop > Voice)
func umodeGreaterThan(l modes.Mode, r modes.Mode) bool {
	for _, mode := range modes.ChannelUserModes {
		if l == mode && r != mode {
			return true
		} else if r == mode {
			return false
		}
	}
	return false
}

// ProcessAccountToUmodeChange processes Add/Remove/List operations for channel persistent usermodes.
func (channel *Channel) ProcessAccountToUmodeChange(client *Client, change modes.ModeChange) (results []modes.ModeChange, err error) {
	changed := false
	defer func() {
		if changed {
			channel.MarkDirty(IncludeLists)
		}
	}()

	account := client.Account()
	isOperChange := client.HasRoleCapabs("chanreg")

	channel.stateMutex.Lock()
	defer channel.stateMutex.Unlock()

	clientMode := channel.accountToUMode[account]
	targetModeNow := channel.accountToUMode[change.Arg]
	var targetModeAfter modes.Mode
	if change.Op == modes.Add {
		targetModeAfter = change.Mode
	}

	// server operators and founders can do anything:
	hasPrivs := isOperChange || (account != "" && account == channel.registeredFounder)
	// halfop and up can list:
	if change.Op == modes.List && (clientMode == modes.Halfop || umodeGreaterThan(clientMode, modes.Halfop)) {
		hasPrivs = true
		// you can do adds or removes at levels you have "privileges over":
	} else if channelUserModeHasPrivsOver(clientMode, targetModeNow) && channelUserModeHasPrivsOver(clientMode, targetModeAfter) {
		hasPrivs = true
		// and you can always de-op yourself:
	} else if change.Op == modes.Remove && account == change.Arg {
		hasPrivs = true
	}
	if !hasPrivs {
		return nil, errInsufficientPrivs
	}

	switch change.Op {
	case modes.Add:
		if targetModeNow != targetModeAfter {
			channel.accountToUMode[change.Arg] = change.Mode
			changed = true
			return []modes.ModeChange{change}, nil
		}
		return nil, nil
	case modes.Remove:
		if targetModeNow == change.Mode {
			delete(channel.accountToUMode, change.Arg)
			changed = true
			return []modes.ModeChange{change}, nil
		}
		return nil, nil
	case modes.List:
		result := make([]modes.ModeChange, len(channel.accountToUMode))
		pos := 0
		for account, mode := range channel.accountToUMode {
			result[pos] = modes.ModeChange{
				Mode: mode,
				Arg:  account,
				Op:   modes.Add,
			}
			pos++
		}
		return result, nil
	default:
		// shouldn't happen
		return nil, errInvalidCharacter
	}
}
