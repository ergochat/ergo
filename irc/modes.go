// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
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
)

// ApplyUserModeChanges applies the given changes, and returns the applied changes.
func ApplyUserModeChanges(client *Client, changes modes.ModeChanges, force bool) modes.ModeChanges {
	applied := make(modes.ModeChanges, 0)

	for _, change := range changes {
		switch change.Mode {
		case modes.Bot, modes.Invisible, modes.WallOps, modes.UserRoleplaying, modes.Operator, modes.LocalOperator, modes.RegisteredOnly:
			switch change.Op {
			case modes.Add:
				if !force && (change.Mode == modes.Operator || change.Mode == modes.LocalOperator) {
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
				if client.SetMode(change.Mode, false) {
					if change.Mode == modes.Invisible {
						client.server.stats.ChangeInvisible(-1)
					} else if change.Mode == modes.Operator || change.Mode == modes.LocalOperator {
						client.server.stats.ChangeOperators(-1)
					}
					applied = append(applied, change)
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

	// return the changes we could actually apply
	return applied
}

// ParseDefaultChannelModes parses the `default-modes` line of the config
func ParseDefaultChannelModes(rawModes *string) modes.Modes {
	if rawModes == nil {
		// not present in config, fall back to compile-time default
		return DefaultChannelModes
	}
	modeChangeStrings := strings.Fields(*rawModes)
	modeChanges, _ := modes.ParseChannelModeChanges(modeChangeStrings...)
	defaultChannelModes := make(modes.Modes, 0)
	for _, modeChange := range modeChanges {
		if modeChange.Op == modes.Add {
			defaultChannelModes = append(defaultChannelModes, modeChange.Mode)
		}
	}
	return defaultChannelModes
}

// ApplyChannelModeChanges applies a given set of mode changes.
func (channel *Channel) ApplyChannelModeChanges(client *Client, isSamode bool, changes modes.ModeChanges, rb *ResponseBuffer) modes.ModeChanges {
	// so we only output one warning for each list type when full
	listFullWarned := make(map[modes.Mode]bool)

	var alreadySentPrivError bool

	applied := make(modes.ModeChanges, 0)

	isListOp := func(change modes.ModeChange) bool {
		return (change.Op == modes.List) || (change.Arg == "")
	}

	hasPrivs := func(change modes.ModeChange) bool {
		if isSamode {
			return true
		}
		switch change.Mode {
		case modes.ChannelFounder, modes.ChannelAdmin, modes.ChannelOperator, modes.Halfop, modes.Voice:
			// List on these modes is a no-op anyway
			if change.Op == modes.List {
				return true
			}
			cfarg, _ := CasefoldName(change.Arg)
			isSelfChange := cfarg == client.NickCasefolded()
			if change.Op == modes.Remove && isSelfChange {
				// "There is no restriction, however, on anyone `deopping' themselves"
				// <https://tools.ietf.org/html/rfc2812#section-3.1.5>
				return true
			}
			return channelUserModeHasPrivsOver(channel.HighestUserMode(client), change.Mode)
		case modes.BanMask:
			// #163: allow unprivileged users to list ban masks
			return isListOp(change) || channel.ClientIsAtLeast(client, modes.ChannelOperator)
		default:
			return channel.ClientIsAtLeast(client, modes.ChannelOperator)
		}
	}

	for _, change := range changes {
		if !hasPrivs(change) {
			if !alreadySentPrivError {
				alreadySentPrivError = true
				rb.Add(nil, client.server.name, ERR_CHANOPRIVSNEEDED, client.Nick(), channel.name, client.t("You're not a channel operator"))
			}
			continue
		}

		switch change.Mode {
		case modes.BanMask, modes.ExceptMask, modes.InviteMask:
			if isListOp(change) {
				channel.ShowMaskList(client, change.Mode, rb)
				continue
			}

			// confirm mask looks valid
			mask, err := Casefold(change.Arg)
			if err != nil {
				continue
			}

			switch change.Op {
			case modes.Add:
				if channel.lists[change.Mode].Length() >= client.server.Limits().ChanListModes {
					if !listFullWarned[change.Mode] {
						rb.Add(nil, client.server.name, ERR_BANLISTFULL, client.Nick(), channel.Name(), change.Mode.String(), client.t("Channel list is full"))
						listFullWarned[change.Mode] = true
					}
					continue
				}

				channel.lists[change.Mode].Add(mask)
				applied = append(applied, change)

			case modes.Remove:
				channel.lists[change.Mode].Remove(mask)
				applied = append(applied, change)
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
				channel.setKey(change.Arg)
				applied = append(applied, change)
			case modes.Remove:
				channel.setKey("")
				applied = append(applied, change)
			}

		case modes.InviteOnly, modes.Moderated, modes.NoOutside, modes.OpOnlyTopic, modes.RegisteredOnly, modes.Secret, modes.ChanRoleplaying:
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
				return nil
			}

			change := channel.applyModeToMember(client, change.Mode, change.Op, nick, rb)
			if change != nil {
				applied = append(applied, *change)
			}
		}
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

	// operators and founders can do anything
	hasPrivs := isOperChange || (account != "" && account == channel.registeredFounder)
	// halfop and up can list, and do add/removes at levels <= their own
	if change.Op == modes.List && (clientMode == modes.Halfop || umodeGreaterThan(clientMode, modes.Halfop)) {
		hasPrivs = true
	} else if channelUserModeHasPrivsOver(clientMode, targetModeNow) && channelUserModeHasPrivsOver(clientMode, targetModeAfter) {
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
