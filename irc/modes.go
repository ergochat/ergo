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
func ParseDefaultChannelModes(config *Config) modes.Modes {
	if config.Channels.DefaultModes == nil {
		// not present in config, fall back to compile-time default
		return DefaultChannelModes
	}
	modeChangeStrings := strings.Split(strings.TrimSpace(*config.Channels.DefaultModes), " ")
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
			// List on these modes is a no-op anyway
			if change.Op == modes.List {
				return true
			}
			cfarg, _ := CasefoldName(change.Arg)
			isSelfChange := cfarg == client.NickCasefolded()
			// Admins can't give other people Admin or remove it from others
			if change.Mode == modes.ChannelAdmin && !isSelfChange {
				return false
			}
			if change.Op == modes.Remove && isSelfChange {
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

			if channel.flags.SetMode(change.Mode, change.Op == modes.Add) {
				applied = append(applied, change)
			}

		case modes.ChannelFounder, modes.ChannelAdmin, modes.ChannelOperator, modes.Halfop, modes.Voice:
			if change.Op == modes.List {
				continue
			}

			nick := change.Arg
			if nick == "" {
				rb.Add(nil, client.server.name, ERR_NEEDMOREPARAMS, "MODE", client.t("Not enough parameters"))
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
