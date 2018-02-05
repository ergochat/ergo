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

// applyUserModeChanges applies the given changes, and returns the applied changes.
func (client *Client) applyUserModeChanges(force bool, changes modes.ModeChanges) modes.ModeChanges {
	applied := make(modes.ModeChanges, 0)

	for _, change := range changes {
		switch change.Mode {
		case modes.Bot, modes.Invisible, modes.WallOps, modes.UserRoleplaying, modes.Operator, modes.LocalOperator, modes.RegisteredOnly:
			switch change.Op {
			case modes.Add:
				if !force && (change.Mode == modes.Operator || change.Mode == modes.LocalOperator) {
					continue
				}

				if client.flags[change.Mode] {
					continue
				}
				client.flags[change.Mode] = true
				applied = append(applied, change)

			case modes.Remove:
				if !client.flags[change.Mode] {
					continue
				}
				delete(client.flags, change.Mode)
				applied = append(applied, change)
			}

		case modes.ServerNotice:
			if !client.flags[modes.Operator] {
				continue
			}
			var masks []sno.Mask
			if change.Op == modes.Add || change.Op == modes.Remove {
				for _, char := range change.Arg {
					masks = append(masks, sno.Mask(char))
				}
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
func ParseDefaultChannelModes(config *Config) modes.Modes {
	if config.Channels.DefaultModes == nil {
		// not present in config, fall back to compile-time default
		return DefaultChannelModes
	}
	modeChangeStrings := strings.Split(strings.TrimSpace(*config.Channels.DefaultModes), " ")
	modeChanges, _ := ParseChannelModeChanges(modeChangeStrings...)
	defaultChannelModes := make(modes.Modes, 0)
	for _, modeChange := range modeChanges {
		if modeChange.Op == modes.Add {
			defaultChannelModes = append(defaultChannelModes, modeChange.Mode)
		}
	}
	return defaultChannelModes
}

// ParseChannelModeChanges returns the valid changes, and the list of unknown chars.
func ParseChannelModeChanges(params ...string) (modes.ModeChanges, map[rune]bool) {
	changes := make(modes.ModeChanges, 0)
	unknown := make(map[rune]bool)

	op := modes.List

	if 0 < len(params) {
		modeArg := params[0]
		skipArgs := 1

		for _, mode := range modeArg {
			if mode == '-' || mode == '+' {
				op = modes.ModeOp(mode)
				continue
			}
			change := modes.ModeChange{
				Mode: modes.Mode(mode),
				Op:   op,
			}

			// put arg into modechange if needed
			switch modes.Mode(mode) {
			case modes.BanMask, modes.ExceptMask, modes.InviteMask:
				if len(params) > skipArgs {
					change.Arg = params[skipArgs]
					skipArgs++
				} else {
					change.Op = modes.List
				}
			case modes.ChannelFounder, modes.ChannelAdmin, modes.ChannelOperator, modes.Halfop, modes.Voice:
				if len(params) > skipArgs {
					change.Arg = params[skipArgs]
					skipArgs++
				} else {
					continue
				}
			case modes.Key, modes.UserLimit:
				// don't require value when removing
				if change.Op == modes.Add {
					if len(params) > skipArgs {
						change.Arg = params[skipArgs]
						skipArgs++
					} else {
						continue
					}
				}
			}

			var isKnown bool
			for _, supportedMode := range modes.SupportedChannelModes {
				if rune(supportedMode) == mode {
					isKnown = true
					break
				}
			}
			for _, supportedMode := range modes.ChannelPrivModes {
				if rune(supportedMode) == mode {
					isKnown = true
					break
				}
			}
			if mode == rune(modes.Voice) {
				isKnown = true
			}
			if !isKnown {
				unknown[mode] = true
				continue
			}

			changes = append(changes, change)
		}
	}

	return changes, unknown
}

// ApplyChannelModeChanges applies a given set of mode changes.
func (channel *Channel) ApplyChannelModeChanges(client *Client, isSamode bool, changes modes.ModeChanges, rb *ResponseBuffer) modes.ModeChanges {
	// so we only output one warning for each list type when full
	listFullWarned := make(map[modes.Mode]bool)

	clientIsOp := channel.ClientIsAtLeast(client, modes.ChannelOperator)
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
			// Admins can't give other people Admin or remove it from others
			if change.Mode == modes.ChannelAdmin {
				return false
			}
			if change.Op == modes.List {
				return true
			}
			cfarg, _ := CasefoldName(change.Arg)
			if change.Op == modes.Remove && cfarg == client.nickCasefolded {
				// "There is no restriction, however, on anyone `deopping' themselves"
				// <https://tools.ietf.org/html/rfc2812#section-3.1.5>
				return true
			}
			return channel.ClientIsAtLeast(client, change.Mode)
		case modes.BanMask:
			// #163: allow unprivileged users to list ban masks
			return clientIsOp || isListOp(change)
		default:
			return clientIsOp
		}
	}

	for _, change := range changes {
		if !hasPrivs(change) {
			if !alreadySentPrivError {
				alreadySentPrivError = true
				rb.Add(nil, client.server.name, ERR_CHANOPRIVSNEEDED, channel.name, client.t("You're not a channel operator"))
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
				val, err := strconv.ParseUint(change.Arg, 10, 64)
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

			case modes.Remove:
				channel.setKey("")
			}
			applied = append(applied, change)

		case modes.InviteOnly, modes.Moderated, modes.NoOutside, modes.OpOnlyTopic, modes.RegisteredOnly, modes.Secret, modes.ChanRoleplaying:
			if change.Op == modes.List {
				continue
			}

			already := channel.setMode(change.Mode, change.Op == modes.Add)
			if !already {
				applied = append(applied, change)
			}

		case modes.ChannelFounder, modes.ChannelAdmin, modes.ChannelOperator, modes.Halfop, modes.Voice:
			if change.Op == modes.List {
				continue
			}

			change := channel.applyModeMemberNoMutex(client, change.Mode, change.Op, change.Arg, rb)
			if change != nil {
				applied = append(applied, *change)
			}
		}
	}

	return applied
}
