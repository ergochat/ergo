package irc

import (
	"strings"
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
)

const (
	Anonymous       ChannelMode = 'a' // flag
	BanMask         ChannelMode = 'b' // arg
	ChannelCreator  ChannelMode = 'O' // flag
	ChannelOperator ChannelMode = 'o' // arg
	ExceptMask      ChannelMode = 'e' // arg
	InviteMask      ChannelMode = 'I' // arg
	InviteOnly      ChannelMode = 'i' // flag
	Key             ChannelMode = 'k' // flag arg
	Moderated       ChannelMode = 'm' // flag
	NoOutside       ChannelMode = 'n' // flag
	OpOnlyTopic     ChannelMode = 't' // flag
	Persistent      ChannelMode = 'P' // flag
	Private         ChannelMode = 'p' // flag
	Quiet           ChannelMode = 'q' // flag
	ReOp            ChannelMode = 'r' // flag
	Secret          ChannelMode = 's' // flag, deprecated
	Theater         ChannelMode = 'T' // flag arg, nonstandard
	UserLimit       ChannelMode = 'l' // flag arg
	Voice           ChannelMode = 'v' // arg
)

var (
	SupportedChannelModes = ChannelModes{
		BanMask, ExceptMask, InviteMask, InviteOnly, Key, NoOutside,
		OpOnlyTopic, Persistent, Private, Theater, UserLimit,
	}
)

//
// commands
//

func (m *ModeCommand) HandleServer(s *Server) {
	client := m.Client()
	target := s.clients.Get(m.nickname)

	if target == nil {
		client.ErrNoSuchNick(m.nickname)
		return
	}

	if client != target && !client.flags[Operator] {
		client.ErrUsersDontMatch()
		return
	}

	changes := make(ModeChanges, 0, len(m.changes))

	for _, change := range m.changes {
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

	// Who should get these replies?
	if len(changes) > 0 {
		client.Reply(RplMode(client, target, changes))
	}
}

func (msg *ChannelModeCommand) HandleServer(server *Server) {
	client := msg.Client()
	channel := server.channels.Get(msg.channel)
	if channel == nil {
		client.ErrNoSuchChannel(msg.channel)
		return
	}

	channel.Mode(client, msg.changes)
}
