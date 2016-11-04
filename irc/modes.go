// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/DanielOaks/girc-go/ircmsg"
)

// user mode flags
type UserMode rune

func (mode UserMode) String() string {
	return string(mode)
}

type UserModes []UserMode

func (modes UserModes) String() string {
	strs := make([]string, len(modes))
	for index, mode := range modes {
		strs[index] = mode.String()
	}
	return strings.Join(strs, "")
}

type ModeChange struct {
	mode UserMode
	op   ModeOp
}

func (change *ModeChange) String() string {
	return fmt.Sprintf("%s%s", change.op, change.mode)
}

type ModeChanges []*ModeChange

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
	return str
}

// channel mode flags
type ChannelMode rune

func (mode ChannelMode) String() string {
	return string(mode)
}

type ChannelModes []ChannelMode

func (modes ChannelModes) String() string {
	strs := make([]string, len(modes))
	for index, mode := range modes {
		strs[index] = mode.String()
	}
	return strings.Join(strs, "")
}

type ChannelModeChange struct {
	mode ChannelMode
	op   ModeOp
	arg  string
}

func (change *ChannelModeChange) String() (str string) {
	if (change.op == Add) || (change.op == Remove) {
		str = change.op.String()
	}
	str += change.mode.String()
	if change.arg != "" {
		str += " " + change.arg
	}
	return
}

type ChannelModeChanges []*ChannelModeChange

func (changes ChannelModeChanges) String() string {
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

type ChannelModeCommand struct {
	channel string
	changes ChannelModeChanges
}

type ModeOp rune

func (op ModeOp) String() string {
	return string(op)
}

const (
	Add    ModeOp = '+'
	List   ModeOp = '='
	Remove ModeOp = '-'
)

const (
	Away            UserMode = 'a'
	Invisible       UserMode = 'i'
	LocalOperator   UserMode = 'O'
	Operator        UserMode = 'o'
	Restricted      UserMode = 'r'
	ServerNotice    UserMode = 's' // deprecated
	TLS             UserMode = 'Z'
	UserRoleplaying UserMode = 'E'
	WallOps         UserMode = 'w'
)

var (
	SupportedUserModes = UserModes{
		Away, Invisible, Operator, UserRoleplaying,
	}
	// supportedUserModesString acts as a cache for when we introduce users
	supportedUserModesString = SupportedUserModes.String()
)

const (
	BanMask         ChannelMode = 'b' // arg
	ChanRoleplaying ChannelMode = 'E' // flag
	ExceptMask      ChannelMode = 'e' // arg
	InviteMask      ChannelMode = 'I' // arg
	InviteOnly      ChannelMode = 'i' // flag
	Key             ChannelMode = 'k' // flag arg
	Moderated       ChannelMode = 'm' // flag
	NoOutside       ChannelMode = 'n' // flag
	OpOnlyTopic     ChannelMode = 't' // flag
	Secret          ChannelMode = 's' // flag
	UserLimit       ChannelMode = 'l' // flag arg
)

var (
	ChannelFounder  ChannelMode = 'q' // arg
	ChannelAdmin    ChannelMode = 'a' // arg
	ChannelOperator ChannelMode = 'o' // arg
	Halfop          ChannelMode = 'h' // arg
	Voice           ChannelMode = 'v' // arg

	SupportedChannelModes = ChannelModes{
		BanMask, ExceptMask, InviteMask, InviteOnly, Key, NoOutside,
		OpOnlyTopic, Secret, UserLimit, ChanRoleplaying,
	}
	// supportedChannelModesString acts as a cache for when we introduce users
	supportedChannelModesString = SupportedChannelModes.String()

	DefaultChannelModes = ChannelModes{
		NoOutside, OpOnlyTopic,
	}

	// ChannelPrivModes holds the list of modes that are privileged, ie founder/op/halfop, in order.
	// voice is not in this list because it cannot perform channel operator actions.
	ChannelPrivModes = ChannelModes{
		ChannelFounder, ChannelAdmin, ChannelOperator, Halfop,
	}

	ChannelModePrefixes = map[ChannelMode]string{
		ChannelFounder:  "~",
		ChannelAdmin:    "&",
		ChannelOperator: "@",
		Halfop:          "%",
		Voice:           "+",
	}
)

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
func GetLowestChannelModePrefix(prefixes string) *ChannelMode {
	var lowest *ChannelMode

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
	} else {
		return umodeHandler(server, client, msg)
	}
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

	//TODO(dan): restricting to Operator here should be done with SAMODE only
	// point SAMODE at this handler too, if they are operator and SAMODE was called then fine
	if client != target && !client.flags[Operator] {
		if len(msg.Params) > 1 {
			client.Send(nil, server.name, ERR_USERSDONTMATCH, client.nick, "Can't change modes for other users")
		} else {
			client.Send(nil, server.name, ERR_USERSDONTMATCH, client.nick, "Can't view modes for other users")
		}
		return false
	}

	// assemble changes
	changes := make(ModeChanges, 0)
	applied := make(ModeChanges, 0)

	if len(msg.Params) > 1 {
		modeArg := msg.Params[1]
		op := ModeOp(modeArg[0])
		if (op == Add) || (op == Remove) {
			modeArg = modeArg[1:]
		} else {
			client.Send(nil, server.name, ERR_UNKNOWNMODE, client.nick, string(modeArg[0]), "is an unknown mode character to me")
			return false
		}

		for _, mode := range modeArg {
			if mode == '-' || mode == '+' {
				op = ModeOp(mode)
				continue
			}
			changes = append(changes, &ModeChange{
				mode: UserMode(mode),
				op:   op,
			})
		}

		for _, change := range changes {
			switch change.mode {
			case Invisible, ServerNotice, WallOps, UserRoleplaying:
				switch change.op {
				case Add:
					if target.flags[change.mode] {
						continue
					}
					target.flags[change.mode] = true
					applied = append(applied, change)

				case Remove:
					if !target.flags[change.mode] {
						continue
					}
					delete(target.flags, change.mode)
					applied = append(applied, change)
				}

			case Operator, LocalOperator:
				if change.op == Remove {
					if !target.flags[change.mode] {
						continue
					}
					delete(target.flags, change.mode)
					applied = append(applied, change)
				}
			}

			// can't do anything to TLS mode
		}
	}

	if len(applied) > 0 {
		client.Send(nil, client.nickMaskString, "MODE", target.nick, applied.String())
	} else if client == target {
		client.Send(nil, target.nickMaskString, RPL_UMODEIS, target.nick, target.ModeString())
	}
	return false
}

// MODE <target> [<modestring> [<mode arguments>...]]
func cmodeHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	channelName, err := CasefoldChannel(msg.Params[0])
	channel := server.channels.Get(channelName)

	if err != nil || channel == nil {
		client.Send(nil, server.name, ERR_NOSUCHCHANNEL, client.nick, msg.Params[0], "No such channel")
		return false
	}

	// assemble changes
	//TODO(dan): split out assembling changes into func that returns changes, err
	changes := make(ChannelModeChanges, 0)
	applied := make(ChannelModeChanges, 0)

	// TODO(dan): look at separating these into the type A/B/C/D args and using those lists here
	if len(msg.Params) > 1 {
		modeArg := msg.Params[1]
		op := ModeOp(modeArg[0])
		if (op == Add) || (op == Remove) {
			modeArg = modeArg[1:]
		} else {
			client.Send(nil, server.name, ERR_UNKNOWNMODE, client.nick, string(modeArg[0]), "is an unknown mode character to me")
			return false
		}

		skipArgs := 2
		for _, mode := range modeArg {
			if mode == '-' || mode == '+' {
				op = ModeOp(mode)
				continue
			}
			change := ChannelModeChange{
				mode: ChannelMode(mode),
				op:   op,
			}

			// put arg into modechange if needed
			switch ChannelMode(mode) {
			case BanMask, ExceptMask, InviteMask:
				if len(msg.Params) > skipArgs {
					change.arg = msg.Params[skipArgs]
					skipArgs++
				} else {
					change.op = List
				}
			case ChannelFounder, ChannelAdmin, ChannelOperator, Halfop, Voice:
				if len(msg.Params) > skipArgs {
					change.arg = msg.Params[skipArgs]
					skipArgs++
				} else {
					continue
				}
			case Key, UserLimit:
				// don't require value when removing
				if change.op == Add {
					if len(msg.Params) > skipArgs {
						change.arg = msg.Params[skipArgs]
						skipArgs++
					} else {
						continue
					}
				}
			}

			changes = append(changes, &change)
		}

		// so we only output one warning for each list type when full
		listFullWarned := make(map[ChannelMode]bool)

		clientIsOp := channel.ClientIsAtLeast(client, ChannelOperator)
		var alreadySentPrivError bool

		for _, change := range changes {
			// chan priv modes are checked specially so ignore them
			// means regular users can't view ban/except lists... but I'm not worried about that
			if ChannelModePrefixes[change.mode] == "" && !clientIsOp {
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
					client.Send(nil, server.name, ERR_UNKNOWNERROR, client.nick, "MODE", "Could not complete MODE command")
					return false
				}

				if (change.op == List) || (mask == "") {
					channel.ShowMaskList(client, change.mode)
					continue
				}

				// confirm mask looks valid
				mask, err = Casefold(mask)
				if err != nil {
					continue
				}

				switch change.op {
				case Add:
					if len(list.masks) >= server.limits.ChanListModes {
						if !listFullWarned[change.mode] {
							client.Send(nil, server.name, ERR_BANLISTFULL, client.nick, channel.name, change.mode.String(), "Channel list is full")
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

			case InviteOnly, Moderated, NoOutside, OpOnlyTopic, Secret, ChanRoleplaying:
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
				var hasPrivs bool

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

				change := channel.applyModeMember(client, change.mode, change.op, change.arg)
				if change != nil {
					applied = append(applied, change)
				}
			}
		}
	}

	if len(applied) > 0 {
		//TODO(dan): we should change the name of String and make it return a slice here
		args := append([]string{channel.name}, strings.Split(applied.String(), " ")...)
		client.Send(nil, client.nickMaskString, "MODE", args...)
	} else {
		//TODO(dan): we should just make ModeString return a slice here
		args := append([]string{client.nick, channel.name}, strings.Split(channel.ModeString(client), " ")...)
		client.Send(nil, client.nickMaskString, RPL_CHANNELMODEIS, args...)
		client.Send(nil, client.nickMaskString, RPL_CHANNELCREATED, client.nick, channel.name, strconv.FormatInt(channel.createdTime.Unix(), 10))
	}
	return false
}
