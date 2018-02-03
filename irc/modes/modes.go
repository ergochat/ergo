// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package modes

import (
	"strings"
)

var (
	// SupportedUserModes are the user modes that we actually support (modifying).
	SupportedUserModes = Modes{
		Away, Bot, Invisible, Operator, RegisteredOnly, ServerNotice, UserRoleplaying,
	}

	// SupportedChannelModes are the channel modes that we support.
	SupportedChannelModes = Modes{
		BanMask, ChanRoleplaying, ExceptMask, InviteMask, InviteOnly, Key,
		Moderated, NoOutside, OpOnlyTopic, RegisteredOnly, Secret, UserLimit,
	}
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
	Mode Mode
	Op   ModeOp
	Arg  string
}

func (change *ModeChange) String() (str string) {
	if (change.Op == Add) || (change.Op == Remove) {
		str = change.Op.String()
	}
	str += change.Mode.String()
	if change.Arg != "" {
		str += " " + change.Arg
	}
	return
}

// ModeChanges are a collection of 'ModeChange's
type ModeChanges []ModeChange

func (changes ModeChanges) String() string {
	if len(changes) == 0 {
		return ""
	}

	op := changes[0].Op
	str := changes[0].Op.String()

	for _, change := range changes {
		if change.Op != op {
			op = change.Op
			str += change.Op.String()
		}
		str += change.Mode.String()
	}

	for _, change := range changes {
		if change.Arg == "" {
			continue
		}
		str += " " + change.Arg
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
	Bot             Mode = 'B'
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

// ParseUserModeChanges returns the valid changes, and the list of unknown chars.
func ParseUserModeChanges(params ...string) (ModeChanges, map[rune]bool) {
	changes := make(ModeChanges, 0)
	unknown := make(map[rune]bool)

	op := List

	if 0 < len(params) {
		modeArg := params[0]
		skipArgs := 1

		for _, mode := range modeArg {
			if mode == '-' || mode == '+' {
				op = ModeOp(mode)
				continue
			}
			change := ModeChange{
				Mode: Mode(mode),
				Op:   op,
			}

			// put arg into modechange if needed
			switch Mode(mode) {
			case ServerNotice:
				// always require arg
				if len(params) > skipArgs {
					change.Arg = params[skipArgs]
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

// ModeSet holds a set of modes.
type ModeSet map[Mode]bool

// String returns the modes in this set.
func (set ModeSet) String() string {
	if len(set) == 0 {
		return ""
	}
	strs := make([]string, len(set))
	index := 0
	for mode := range set {
		strs[index] = mode.String()
		index++
	}
	return strings.Join(strs, "")
}

// Prefixes returns a list of prefixes for the given set of channel modes.
func (set ModeSet) Prefixes(isMultiPrefix bool) string {
	var prefixes string

	// add prefixes in order from highest to lowest privs
	for _, mode := range ChannelPrivModes {
		if set[mode] {
			prefixes += ChannelModePrefixes[mode]
		}
	}
	if set[Voice] {
		prefixes += ChannelModePrefixes[Voice]
	}

	if !isMultiPrefix && len(prefixes) > 1 {
		prefixes = string(prefixes[0])
	}

	return prefixes
}
