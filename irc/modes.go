// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
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
	Away          UserMode = 'a'
	Invisible     UserMode = 'i'
	LocalOperator UserMode = 'O'
	Operator      UserMode = 'o'
	Restricted    UserMode = 'r'
	ServerNotice  UserMode = 's' // deprecated
	WallOps       UserMode = 'w'
)

var (
	SupportedUserModes = UserModes{
		Away, Invisible, Operator,
	}
	// supportedUserModesString acts as a cache for when we introduce users
	supportedUserModesString = SupportedUserModes.String()
)

const (
	ChannelFounder  ChannelMode = 'q' // arg
	ChannelAdmin    ChannelMode = 'a' // arg
	ChannelOperator ChannelMode = 'o' // arg
	Halfop          ChannelMode = 'h' // arg
	Voice           ChannelMode = 'v' // arg

	BanMask     ChannelMode = 'b' // arg
	ExceptMask  ChannelMode = 'e' // arg
	InviteMask  ChannelMode = 'I' // arg
	InviteOnly  ChannelMode = 'i' // flag
	Key         ChannelMode = 'k' // flag arg
	Moderated   ChannelMode = 'm' // flag
	NoOutside   ChannelMode = 'n' // flag
	OpOnlyTopic ChannelMode = 't' // flag
	Persistent  ChannelMode = 'P' // flag
	ReOp        ChannelMode = 'r' // flag
	Secret      ChannelMode = 's' // flag
	Theater     ChannelMode = 'T' // flag, nonstandard
	UserLimit   ChannelMode = 'l' // flag arg
)

var (
	SupportedChannelModes = ChannelModes{
		BanMask, ExceptMask, InviteMask, InviteOnly, Key, NoOutside,
		OpOnlyTopic, Persistent, Secret, Theater, UserLimit,
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

//
// commands
//

// MODE <target> [<modestring> [<mode arguments>...]]
func modeHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	name := NewName(msg.Params[0])
	if name.IsChannel() {
		// return cmodeHandler(server, client, msg)
		client.Notice("CMODEs are not yet supported!")
		return false
	} else {
		return umodeHandler(server, client, msg)
	}
}

// MODE <target> [<modestring> [<mode arguments>...]]
func umodeHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	nickname := NewName(msg.Params[0])

	target := server.clients.Get(nickname)

	if target == nil {
		client.Send(nil, server.nameString, ERR_NOSUCHNICK, client.nickString, msg.Params[0], "No such nick")
		return false
	}

	//TODO(dan): restricting to Operator here should be done with SAMODE only
	// point SAMODE at this handler too, if they are operator and SAMODE was called then fine
	if client != target && !client.flags[Operator] {
		if len(msg.Params) > 1 {
			client.Send(nil, server.nameString, ERR_USERSDONTMATCH, client.nickString, "Can't change modes for other users")
		} else {
			client.Send(nil, server.nameString, ERR_USERSDONTMATCH, client.nickString, "Can't view modes for other users")
		}
		return false
	}

	// assemble changes
	changes := make(ModeChanges, 0)

	if len(msg.Params) > 1 {
		modeArg := msg.Params[0]
		op := ModeOp(modeArg[0])
		if (op == Add) || (op == Remove) {
			modeArg = modeArg[1:]
		} else {
			client.Send(nil, server.nameString, ERR_UNKNOWNERROR, client.nickString, "MODE", "Mode string could not be parsed correctly")
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
			case Invisible, ServerNotice, WallOps:
				switch change.op {
				case Add:
					if target.flags[change.mode] {
						continue
					}
					target.flags[change.mode] = true
					changes = append(changes, change)

				case Remove:
					if !target.flags[change.mode] {
						continue
					}
					delete(target.flags, change.mode)
					changes = append(changes, change)
				}

			case Operator, LocalOperator:
				if change.op == Remove {
					if !target.flags[change.mode] {
						continue
					}
					delete(target.flags, change.mode)
					changes = append(changes, change)
				}
			}
		}
	}

	if len(changes) > 0 {
		client.Send(nil, client.nickMaskString, "MODE", target.nickString, changes.String())
	} else if client == target {
		client.Send(nil, target.nickMaskString, RPL_UMODEIS, target.nickString, target.ModeString())
	}
	return false
}

/*
func (msg *ChannelModeCommand) HandleServer(server *Server) {
	client := msg.Client()
	channel := server.channels.Get(msg.channel)
	if channel == nil {
		client.ErrNoSuchChannel(msg.channel)
		return
	}

	channel.Mode(client, msg.changes)
}
*/
