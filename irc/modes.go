// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"strconv"
	"strings"

	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/oragono/oragono/irc/sno"
	"github.com/tidwall/buntdb"
)

// ModeOp is an operation performed with modes
type ModeOp rune

func (op ModeOp) String() string {
	return string(op)
}

const (
	// Add is used when adding the given key.
	Add ModeOp = '+'
	// List is used when listing modes (for instance, listing the current bans on a channel).
	List ModeOp = '='
	// Remove is used when taking away the given key.
	Remove ModeOp = '-'
)

// Mode represents a user/channel/server mode
type Mode rune

func (mode Mode) String() string {
	return string(mode)
}

// ModeChange is a single mode changing
type ModeChange struct {
	mode Mode
	op   ModeOp
	arg  string
}

func (change *ModeChange) String() (str string) {
	if (change.op == Add) || (change.op == Remove) {
		str = change.op.String()
	}
	str += change.mode.String()
	if change.arg != "" {
		str += " " + change.arg
	}
	return
}

// ModeChanges are a collection of 'ModeChange's
type ModeChanges []ModeChange

func (changes ModeChanges) String() string {
	if len(changes) == 0 {
		return ""
	}

	op := changes[0].op
	str := changes[0].op.String()

	for _, change := range changes {
		if change.op != op {
			op = change.op
			str += change.op.String()
		}
		str += change.mode.String()
	}

	for _, change := range changes {
		if change.arg == "" {
			continue
		}
		str += " " + change.arg
	}
	return str
}

// Modes is just a raw list of modes
type Modes []Mode

func (modes Modes) String() string {
	strs := make([]string, len(modes))
	for index, mode := range modes {
		strs[index] = mode.String()
	}
	return strings.Join(strs, "")
}

// User Modes
const (
	Away            Mode = 'a'
	Invisible       Mode = 'i'
	LocalOperator   Mode = 'O'
	Operator        Mode = 'o'
	Restricted      Mode = 'r'
	RegisteredOnly  Mode = 'R'
	ServerNotice    Mode = 's'
	TLS             Mode = 'Z'
	UserRoleplaying Mode = 'E'
	WallOps         Mode = 'w'
)

var (
	// SupportedUserModes are the user modes that we actually support (modifying).
	SupportedUserModes = Modes{
		Away, Invisible, Operator, RegisteredOnly, ServerNotice, UserRoleplaying,
	}
	// supportedUserModesString acts as a cache for when we introduce users
	supportedUserModesString = SupportedUserModes.String()
)

// Channel Modes
const (
	BanMask         Mode = 'b' // arg
	ChanRoleplaying Mode = 'E' // flag
	ExceptMask      Mode = 'e' // arg
	InviteMask      Mode = 'I' // arg
	InviteOnly      Mode = 'i' // flag
	Key             Mode = 'k' // flag arg
	Moderated       Mode = 'm' // flag
	NoOutside       Mode = 'n' // flag
	OpOnlyTopic     Mode = 't' // flag
	// RegisteredOnly mode is reused here from umode definition
	Secret    Mode = 's' // flag
	UserLimit Mode = 'l' // flag arg
)

var (
	ChannelFounder  Mode = 'q' // arg
	ChannelAdmin    Mode = 'a' // arg
	ChannelOperator Mode = 'o' // arg
	Halfop          Mode = 'h' // arg
	Voice           Mode = 'v' // arg

	// SupportedChannelModes are the channel modes that we support.
	SupportedChannelModes = Modes{
		BanMask, ExceptMask, InviteMask, InviteOnly, Key, NoOutside,
		OpOnlyTopic, Secret, UserLimit, ChanRoleplaying,
	}
	// supportedChannelModesString acts as a cache for when we introduce users
	supportedChannelModesString = SupportedChannelModes.String()

	// DefaultChannelModes are enabled on brand new channels when they're created.
	// this can be overridden in the `channels` config, with the `default-modes` key
	DefaultChannelModes = Modes{
		NoOutside, OpOnlyTopic,
	}

	// ChannelPrivModes holds the list of modes that are privileged, ie founder/op/halfop, in order.
	// voice is not in this list because it cannot perform channel operator actions.
	ChannelPrivModes = Modes{
		ChannelFounder, ChannelAdmin, ChannelOperator, Halfop,
	}

	ChannelModePrefixes = map[Mode]string{
		ChannelFounder:  "~",
		ChannelAdmin:    "&",
		ChannelOperator: "@",
		Halfop:          "%",
		Voice:           "+",
	}
)

//
// channel membership prefixes
//

// SplitChannelMembershipPrefixes takes a target and returns the prefixes on it, then the name.
func SplitChannelMembershipPrefixes(target string) (prefixes string, name string) {
	name = target
	for {
		if len(name) > 0 && strings.Contains("~&@%+", string(name[0])) {
			prefixes += string(name[0])
			name = name[1:]
		} else {
			break
		}
	}

	return prefixes, name
}

// GetLowestChannelModePrefix returns the lowest channel prefix mode out of the given prefixes.
func GetLowestChannelModePrefix(prefixes string) *Mode {
	var lowest *Mode

	if strings.Contains(prefixes, "+") {
		lowest = &Voice
	} else {
		for i, mode := range ChannelPrivModes {
			if strings.Contains(prefixes, ChannelModePrefixes[mode]) {
				lowest = &ChannelPrivModes[i]
			}
		}
	}

	return lowest
}

//
// commands
//

// MODE <target> [<modestring> [<mode arguments>...]]
func modeHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	_, errChan := CasefoldChannel(msg.Params[0])

	if errChan == nil {
		return cmodeHandler(server, client, msg)
	}
	return umodeHandler(server, client, msg)
}

// ParseUserModeChanges returns the valid changes, and the list of unknown chars.
func ParseUserModeChanges(params ...string) (ModeChanges, map[rune]bool) {
	changes := make(ModeChanges, 0)
	unknown := make(map[rune]bool)

	if 0 < len(params) {
		modeArg := params[0]
		op := ModeOp(modeArg[0])
		if (op == Add) || (op == Remove) {
			modeArg = modeArg[1:]
		} else {
			unknown[rune(modeArg[0])] = true
			return changes, unknown
		}

		skipArgs := 1

		for _, mode := range modeArg {
			if mode == '-' || mode == '+' {
				op = ModeOp(mode)
				continue
			}
			change := ModeChange{
				mode: Mode(mode),
				op:   op,
			}

			// put arg into modechange if needed
			switch Mode(mode) {
			case ServerNotice:
				// always require arg
				if len(params) > skipArgs {
					change.arg = params[skipArgs]
					skipArgs++
				} else {
					continue
				}
			}

			var isKnown bool
			for _, supportedMode := range SupportedUserModes {
				if rune(supportedMode) == mode {
					isKnown = true
					break
				}
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

// applyUserModeChanges applies the given changes, and returns the applied changes.
func (client *Client) applyUserModeChanges(force bool, changes ModeChanges) ModeChanges {
	applied := make(ModeChanges, 0)

	for _, change := range changes {
		switch change.mode {
		case Invisible, WallOps, UserRoleplaying, Operator, LocalOperator, RegisteredOnly:
			switch change.op {
			case Add:
				if !force && (change.mode == Operator || change.mode == LocalOperator) {
					continue
				}

				if client.flags[change.mode] {
					continue
				}
				client.flags[change.mode] = true
				applied = append(applied, change)

			case Remove:
				if !client.flags[change.mode] {
					continue
				}
				delete(client.flags, change.mode)
				applied = append(applied, change)
			}

		case ServerNotice:
			if !client.flags[Operator] {
				continue
			}
			var masks []sno.Mask
			if change.op == Add || change.op == Remove {
				for _, char := range change.arg {
					masks = append(masks, sno.Mask(char))
				}
			}
			if change.op == Add {
				client.server.snomasks.AddMasks(client, masks...)
				applied = append(applied, change)
			} else if change.op == Remove {
				client.server.snomasks.RemoveMasks(client, masks...)
				applied = append(applied, change)
			}
		}

		// can't do anything to TLS mode
	}

	// return the changes we could actually apply
	return applied
}

// MODE <target> [<modestring> [<mode arguments>...]]
func umodeHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	nickname, err := CasefoldName(msg.Params[0])

	target := server.clients.Get(nickname)

	if err != nil || target == nil {
		if len(msg.Params[0]) > 0 {
			client.Send(nil, server.name, ERR_NOSUCHNICK, client.nick, msg.Params[0], "No such nick")
		}
		return false
	}

	if client != target && msg.Command != "SAMODE" {
		if len(msg.Params) > 1 {
			client.Send(nil, server.name, ERR_USERSDONTMATCH, client.nick, "Can't change modes for other users")
		} else {
			client.Send(nil, server.name, ERR_USERSDONTMATCH, client.nick, "Can't view modes for other users")
		}
		return false
	}

	// applied mode changes
	applied := make(ModeChanges, 0)

	if 1 < len(msg.Params) {
		// parse out real mode changes
		params := msg.Params[1:]
		changes, unknown := ParseUserModeChanges(params...)

		// alert for unknown mode changes
		for char := range unknown {
			client.Send(nil, server.name, ERR_UNKNOWNMODE, client.nick, string(char), "is an unknown mode character to me")
		}
		if len(unknown) == 1 && len(changes) == 0 {
			return false
		}

		// apply mode changes
		applied = target.applyUserModeChanges(msg.Command == "SAMODE", changes)
	}

	if len(applied) > 0 {
		client.Send(nil, client.nickMaskString, "MODE", target.nick, applied.String())
	} else if client == target {
		client.Send(nil, target.nickMaskString, RPL_UMODEIS, target.nick, target.ModeString())
		if client.flags[LocalOperator] || client.flags[Operator] {
			masks := server.snomasks.String(client)
			if 0 < len(masks) {
				client.Send(nil, target.nickMaskString, RPL_SNOMASKIS, target.nick, masks, "Server notice masks")
			}
		}
	}
	return false
}

// ParseDefaultChannelModes parses the `default-modes` line of the config
func ParseDefaultChannelModes(config *Config) Modes {
	if config.Channels.DefaultModes == nil {
		// not present in config, fall back to compile-time default
		return DefaultChannelModes
	}
	modeChangeStrings := strings.Split(strings.TrimSpace(*config.Channels.DefaultModes), " ")
	modeChanges, _ := ParseChannelModeChanges(modeChangeStrings...)
	defaultChannelModes := make(Modes, 0)
	for _, modeChange := range modeChanges {
		if modeChange.op == Add {
			defaultChannelModes = append(defaultChannelModes, modeChange.mode)
		}
	}
	return defaultChannelModes
}

// ParseChannelModeChanges returns the valid changes, and the list of unknown chars.
func ParseChannelModeChanges(params ...string) (ModeChanges, map[rune]bool) {
	changes := make(ModeChanges, 0)
	unknown := make(map[rune]bool)

	if 0 < len(params) {
		modeArg := params[0]
		if len(modeArg) == 0 {
			return changes, unknown
		}
		op := ModeOp(modeArg[0])
		if (op == Add) || (op == Remove) {
			modeArg = modeArg[1:]
		} else {
			unknown[rune(modeArg[0])] = true
			return changes, unknown
		}

		skipArgs := 1

		for _, mode := range modeArg {
			if mode == '-' || mode == '+' {
				op = ModeOp(mode)
				continue
			}
			change := ModeChange{
				mode: Mode(mode),
				op:   op,
			}

			// put arg into modechange if needed
			switch Mode(mode) {
			case BanMask, ExceptMask, InviteMask:
				if len(params) > skipArgs {
					change.arg = params[skipArgs]
					skipArgs++
				} else {
					change.op = List
				}
			case ChannelFounder, ChannelAdmin, ChannelOperator, Halfop, Voice:
				if len(params) > skipArgs {
					change.arg = params[skipArgs]
					skipArgs++
				} else {
					continue
				}
			case Key, UserLimit:
				// don't require value when removing
				if change.op == Add {
					if len(params) > skipArgs {
						change.arg = params[skipArgs]
						skipArgs++
					} else {
						continue
					}
				}
			}

			var isKnown bool
			for _, supportedMode := range SupportedChannelModes {
				if rune(supportedMode) == mode {
					isKnown = true
					break
				}
			}
			for _, supportedMode := range ChannelPrivModes {
				if rune(supportedMode) == mode {
					isKnown = true
					break
				}
			}
			if mode == rune(Voice) {
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
func ApplyChannelModeChanges(channel *Channel, client *Client, isSamode bool, changes ModeChanges) ModeChanges {
	// so we only output one warning for each list type when full
	listFullWarned := make(map[Mode]bool)

	clientIsOp := channel.clientIsAtLeastNoMutex(client, ChannelOperator)
	var alreadySentPrivError bool

	applied := make(ModeChanges, 0)

	for _, change := range changes {
		// chan priv modes are checked specially so ignore them
		// means regular users can't view ban/except lists... but I'm not worried about that
		if isSamode && ChannelModePrefixes[change.mode] == "" && !clientIsOp {
			if !alreadySentPrivError {
				alreadySentPrivError = true
				client.Send(nil, client.server.name, ERR_CHANOPRIVSNEEDED, channel.name, "You're not a channel operator")
			}
			continue
		}

		switch change.mode {
		case BanMask, ExceptMask, InviteMask:
			mask := change.arg
			list := channel.lists[change.mode]
			if list == nil {
				// This should never happen, but better safe than panicky.
				client.Send(nil, client.server.name, ERR_UNKNOWNERROR, client.nick, "MODE", "Could not complete MODE command")
				return changes
			}

			if (change.op == List) || (mask == "") {
				channel.ShowMaskList(client, change.mode)
				continue
			}

			// confirm mask looks valid
			mask, err := Casefold(mask)
			if err != nil {
				continue
			}

			switch change.op {
			case Add:
				if len(list.masks) >= client.server.limits.ChanListModes {
					if !listFullWarned[change.mode] {
						client.Send(nil, client.server.name, ERR_BANLISTFULL, client.nick, channel.name, change.mode.String(), "Channel list is full")
						listFullWarned[change.mode] = true
					}
					continue
				}

				list.Add(mask)
				applied = append(applied, change)

			case Remove:
				list.Remove(mask)
				applied = append(applied, change)
			}

		case UserLimit:
			switch change.op {
			case Add:
				val, err := strconv.ParseUint(change.arg, 10, 64)
				if err == nil {
					channel.userLimit = val
					applied = append(applied, change)
				}

			case Remove:
				channel.userLimit = 0
				applied = append(applied, change)
			}

		case Key:
			switch change.op {
			case Add:
				channel.key = change.arg

			case Remove:
				channel.key = ""
			}
			applied = append(applied, change)

		case InviteOnly, Moderated, NoOutside, OpOnlyTopic, RegisteredOnly, Secret, ChanRoleplaying:
			switch change.op {
			case Add:
				if channel.flags[change.mode] {
					continue
				}
				channel.flags[change.mode] = true
				applied = append(applied, change)

			case Remove:
				if !channel.flags[change.mode] {
					continue
				}
				delete(channel.flags, change.mode)
				applied = append(applied, change)
			}

		case ChannelFounder, ChannelAdmin, ChannelOperator, Halfop, Voice:
			// make sure client has privs to edit the given prefix
			hasPrivs := isSamode

			if !hasPrivs {
				for _, mode := range ChannelPrivModes {
					if channel.members[client][mode] {
						hasPrivs = true

						// Admins can't give other people Admin or remove it from others,
						// standard for that channel mode, we worry about this later
						if mode == ChannelAdmin && change.mode == ChannelAdmin {
							hasPrivs = false
						}

						break
					} else if mode == change.mode {
						break
					}
				}
			}

			casefoldedName, err := CasefoldName(change.arg)
			if err != nil {
				continue
			}

			if !hasPrivs {
				if change.op == Remove && casefoldedName == client.nickCasefolded {
					// success!
				} else {
					if !alreadySentPrivError {
						alreadySentPrivError = true
						client.Send(nil, client.server.name, ERR_CHANOPRIVSNEEDED, channel.name, "You're not a channel operator")
					}
					continue
				}
			}

			change := channel.applyModeMemberNoMutex(client, change.mode, change.op, change.arg)
			if change != nil {
				applied = append(applied, *change)
			}
		}
	}

	return applied
}

// MODE <target> [<modestring> [<mode arguments>...]]
func cmodeHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	channelName, err := CasefoldChannel(msg.Params[0])
	channel := server.channels.Get(channelName)

	if err != nil || channel == nil {
		client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, msg.Params[0], "No such channel")
		return false
	}

	channel.membersMutex.Lock()
	defer channel.membersMutex.Unlock()

	// applied mode changes
	applied := make(ModeChanges, 0)

	if 1 < len(msg.Params) {
		// parse out real mode changes
		params := msg.Params[1:]
		changes, unknown := ParseChannelModeChanges(params...)

		// alert for unknown mode changes
		for char := range unknown {
			client.Send(nil, server.name, ERR_UNKNOWNMODE, client.nick, string(char), "is an unknown mode character to me")
		}
		if len(unknown) == 1 && len(changes) == 0 {
			return false
		}

		// apply mode changes
		applied = ApplyChannelModeChanges(channel, client, msg.Command == "SAMODE", changes)
	}

	// save changes to banlist/exceptlist/invexlist
	var banlistUpdated, exceptlistUpdated, invexlistUpdated bool
	for _, change := range applied {
		if change.mode == BanMask {
			banlistUpdated = true
		} else if change.mode == ExceptMask {
			exceptlistUpdated = true
		} else if change.mode == InviteMask {
			invexlistUpdated = true
		}
	}

	server.registeredChannelsMutex.Lock()
	if 0 < len(applied) && server.registeredChannels[channel.nameCasefolded] != nil && (banlistUpdated || exceptlistUpdated || invexlistUpdated) {
		server.store.Update(func(tx *buntdb.Tx) error {
			chanInfo := server.loadChannelNoMutex(tx, channel.nameCasefolded)

			if banlistUpdated {
				var banlist []string
				for mask := range channel.lists[BanMask].masks {
					banlist = append(banlist, mask)
				}
				chanInfo.Banlist = banlist
			}
			if exceptlistUpdated {
				var exceptlist []string
				for mask := range channel.lists[ExceptMask].masks {
					exceptlist = append(exceptlist, mask)
				}
				chanInfo.Exceptlist = exceptlist
			}
			if invexlistUpdated {
				var invitelist []string
				for mask := range channel.lists[InviteMask].masks {
					invitelist = append(invitelist, mask)
				}
				chanInfo.Invitelist = invitelist
			}

			server.saveChannelNoMutex(tx, channel.nameCasefolded, *chanInfo)

			return nil
		})
	}
	server.registeredChannelsMutex.Unlock()

	// send out changes
	if len(applied) > 0 {
		//TODO(dan): we should change the name of String and make it return a slice here
		args := append([]string{channel.name}, strings.Split(applied.String(), " ")...)
		for member := range channel.members {
			member.Send(nil, client.nickMaskString, "MODE", args...)
		}
	} else {
		//TODO(dan): we should just make ModeString return a slice here
		args := append([]string{client.nick, channel.name}, strings.Split(channel.modeStringNoLock(client), " ")...)
		client.Send(nil, client.nickMaskString, RPL_CHANNELMODEIS, args...)
		client.Send(nil, client.nickMaskString, RPL_CHANNELCREATED, client.nick, channel.name, strconv.FormatInt(channel.createdTime.Unix(), 10))
	}
	return false
}
