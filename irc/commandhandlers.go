// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import "fmt"

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

/*
type ModeCommand struct {
	BaseCommand
	nickname Name
	changes  ModeChanges
}

// MODE <nickname> ( "+" / "-" )? *( "+" / "-" / <mode character> )
func ParseUserModeCommand(nickname Name, args []string) (Command, error) {
	cmd := &ModeCommand{
		nickname: nickname,
		changes:  make(ModeChanges, 0),
	}

	// account for MODE command with no args to list things
	if len(args) < 1 {
		// don't do any further processing
		return cmd, nil
	}

	modeArg := args[0]
	op := ModeOp(modeArg[0])
	if (op == Add) || (op == Remove) {
		modeArg = modeArg[1:]
	} else {
		return nil, ErrParseCommand
	}

	for _, mode := range modeArg {
		if mode == '-' || mode == '+' {
			op = ModeOp(mode)
			continue
		}
		cmd.changes = append(cmd.changes, &ModeChange{
			mode: UserMode(mode),
			op:   op,
		})
	}

	return cmd, nil
}
*/

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
	channel Name
	changes ChannelModeChanges
}

// MODE <channel> ( "+" / "-" )? *( "+" / "-" / <mode character> ) *<modeparams>
func ParseChannelModeCommand(channel Name, args []string) (Command, error) {
	cmd := &ChannelModeCommand{
		channel: channel,
		changes: make(ChannelModeChanges, 0),
	}

	// account for MODE command with no args to list things
	if len(args) < 1 {
		// don't do any further processing
		return cmd, nil
	}

	modeArg := args[0]
	op := ModeOp(modeArg[0])
	if (op == Add) || (op == Remove) {
		modeArg = modeArg[1:]
	} else {
		return nil, ErrParseCommand
	}

	currentArgIndex := 1

	for _, mode := range modeArg {
		if mode == '-' || mode == '+' {
			op = ModeOp(mode)
			continue
		}
		change := &ChannelModeChange{
			mode: ChannelMode(mode),
			op:   op,
		}
		switch change.mode {
		// TODO(dan): separate this into the type A/B/C/D args and use those lists here
		case Key, BanMask, ExceptMask, InviteMask, UserLimit,
			ChannelOperator, ChannelFounder, ChannelAdmin, Halfop, Voice:
			if len(args) > currentArgIndex {
				change.arg = args[currentArgIndex]
				currentArgIndex++
			} else {
				// silently skip this mode
				continue
			}
		}
		cmd.changes = append(cmd.changes, change)
	}

	return cmd, nil
}

/*

func ParseModeCommand(args []string) (Command, error) {
	name := NewName(args[0])
	if name.IsChannel() {
		return ParseChannelModeCommand(name, args[1:])
	} else {
		return ParseUserModeCommand(name, args[1:])
	}
}

type WhoisCommand struct {
	BaseCommand
	target Name
	masks  []Name
}

// WHOIS [ <target> ] <mask> *( "," <mask> )
func ParseWhoisCommand(args []string) (Command, error) {
	var masks string
	var target string

	if len(args) > 1 {
		target = args[0]
		masks = args[1]
	} else {
		masks = args[0]
	}

	return &WhoisCommand{
		target: NewName(target),
		masks:  NewNames(strings.Split(masks, ",")),
	}, nil
}

type WhoCommand struct {
	BaseCommand
	mask         Name
	operatorOnly bool
}

// WHO [ <mask> [ "o" ] ]
func ParseWhoCommand(args []string) (Command, error) {
	cmd := &WhoCommand{}

	if len(args) > 0 {
		cmd.mask = NewName(args[0])
	}

	if (len(args) > 1) && (args[1] == "o") {
		cmd.operatorOnly = true
	}

	return cmd, nil
}

type OperCommand struct {
	PassCommand
	name Name
}

func (msg *OperCommand) LoadPassword(server *Server) {
	msg.hash = server.operators[msg.name]
}

// OPER <name> <password>
func ParseOperCommand(args []string) (Command, error) {
	cmd := &OperCommand{
		name: NewName(args[0]),
	}
	cmd.password = []byte(args[1])
	return cmd, nil
}

type CapCommand struct {
	BaseCommand
	subCommand   CapSubCommand
	capabilities CapabilitySet
}

func ParseCapCommand(args []string) (Command, error) {
	cmd := &CapCommand{
		subCommand:   CapSubCommand(strings.ToUpper(args[0])),
		capabilities: make(CapabilitySet),
	}

	if len(args) > 1 {
		strs := spacesExpr.Split(args[1], -1)
		for _, str := range strs {
			cmd.capabilities[Capability(str)] = true
		}
	}
	return cmd, nil
}

// HAPROXY support
type ProxyCommand struct {
	BaseCommand
	net        Name
	sourceIP   Name
	destIP     Name
	sourcePort Name
	destPort   Name
	hostname   Name // looked up in socket thread
}

func NewProxyCommand(hostname Name) *ProxyCommand {
	cmd := &ProxyCommand{
		hostname: hostname,
	}
	cmd.code = PROXY
	return cmd
}

func ParseProxyCommand(args []string) (Command, error) {
	return &ProxyCommand{
		net:        NewName(args[0]),
		sourceIP:   NewName(args[1]),
		destIP:     NewName(args[2]),
		sourcePort: NewName(args[3]),
		destPort:   NewName(args[4]),
		hostname:   LookupHostname(NewName(args[1])),
	}, nil
}

type AwayCommand struct {
	BaseCommand
	text Text
}

func ParseAwayCommand(args []string) (Command, error) {
	cmd := &AwayCommand{}

	if len(args) > 0 {
		cmd.text = NewText(args[0])
	}

	return cmd, nil
}

type IsOnCommand struct {
	BaseCommand
	nicks []Name
}

func ParseIsOnCommand(args []string) (Command, error) {
	return &IsOnCommand{
		nicks: NewNames(args),
	}, nil
}

type MOTDCommand struct {
	BaseCommand
	target Name
}

func ParseMOTDCommand(args []string) (Command, error) {
	cmd := &MOTDCommand{}
	if len(args) > 0 {
		cmd.target = NewName(args[0])
	}
	return cmd, nil
}

type NoticeCommand struct {
	BaseCommand
	target  Name
	message Text
}

func ParseNoticeCommand(args []string) (Command, error) {
	return &NoticeCommand{
		target:  NewName(args[0]),
		message: NewText(args[1]),
	}, nil
}

type KickCommand struct {
	BaseCommand
	kicks   map[Name]Name
	comment Text
}

func (msg *KickCommand) Comment() Text {
	if msg.comment == "" {
		return msg.Client().Nick().Text()
	}
	return msg.comment
}

func ParseKickCommand(args []string) (Command, error) {
	channels := NewNames(strings.Split(args[0], ","))
	users := NewNames(strings.Split(args[1], ","))
	if (len(channels) != len(users)) && (len(users) != 1) {
		return nil, NotEnoughArgsError
	}
	cmd := &KickCommand{
		kicks: make(map[Name]Name),
	}
	for index, channel := range channels {
		if len(users) == 1 {
			cmd.kicks[channel] = users[0]
		} else {
			cmd.kicks[channel] = users[index]
		}
	}
	if len(args) > 2 {
		cmd.comment = NewText(args[2])
	}
	return cmd, nil
}

type ListCommand struct {
	BaseCommand
	channels []Name
	target   Name
}

func ParseListCommand(args []string) (Command, error) {
	cmd := &ListCommand{}
	if len(args) > 0 {
		cmd.channels = NewNames(strings.Split(args[0], ","))
	}
	if len(args) > 1 {
		cmd.target = NewName(args[1])
	}
	return cmd, nil
}

type NamesCommand struct {
	BaseCommand
	channels []Name
	target   Name
}

func ParseNamesCommand(args []string) (Command, error) {
	cmd := &NamesCommand{}
	if len(args) > 0 {
		cmd.channels = NewNames(strings.Split(args[0], ","))
	}
	if len(args) > 1 {
		cmd.target = NewName(args[1])
	}
	return cmd, nil
}

type DebugCommand struct {
	BaseCommand
	subCommand Name
}

func ParseDebugCommand(args []string) (Command, error) {
	return &DebugCommand{
		subCommand: NewName(strings.ToUpper(args[0])),
	}, nil
}

type VersionCommand struct {
	BaseCommand
	target Name
}

func ParseVersionCommand(args []string) (Command, error) {
	cmd := &VersionCommand{}
	if len(args) > 0 {
		cmd.target = NewName(args[0])
	}
	return cmd, nil
}

type InviteCommand struct {
	BaseCommand
	nickname Name
	channel  Name
}

func ParseInviteCommand(args []string) (Command, error) {
	return &InviteCommand{
		nickname: NewName(args[0]),
		channel:  NewName(args[1]),
	}, nil
}

func ParseTheaterCommand(args []string) (Command, error) {
	if upperSubCmd := strings.ToUpper(args[0]); upperSubCmd == "IDENTIFY" && len(args) == 3 {
		return &TheaterIdentifyCommand{
			channel:     NewName(args[1]),
			PassCommand: PassCommand{password: []byte(args[2])},
		}, nil
	} else if upperSubCmd == "PRIVMSG" && len(args) == 4 {
		return &TheaterPrivMsgCommand{
			channel: NewName(args[1]),
			asNick:  NewName(args[2]),
			message: NewText(args[3]),
		}, nil
	} else if upperSubCmd == "ACTION" && len(args) == 4 {
		return &TheaterActionCommand{
			channel: NewName(args[1]),
			asNick:  NewName(args[2]),
			action:  NewCTCPText(args[3]),
		}, nil
	} else {
		return nil, ErrParseCommand
	}
}

type TimeCommand struct {
	BaseCommand
	target Name
}

func ParseTimeCommand(args []string) (Command, error) {
	cmd := &TimeCommand{}
	if len(args) > 0 {
		cmd.target = NewName(args[0])
	}
	return cmd, nil
}

type KillCommand struct {
	BaseCommand
	nickname Name
	comment  Text
}

func ParseKillCommand(args []string) (Command, error) {
	return &KillCommand{
		nickname: NewName(args[0]),
		comment:  NewText(args[1]),
	}, nil
}

type WhoWasCommand struct {
	BaseCommand
	nicknames []Name
	count     int64
	target    Name
}

func ParseWhoWasCommand(args []string) (Command, error) {
	cmd := &WhoWasCommand{
		nicknames: NewNames(strings.Split(args[0], ",")),
	}
	if len(args) > 1 {
		cmd.count, _ = strconv.ParseInt(args[1], 10, 64)
	}
	if len(args) > 2 {
		cmd.target = NewName(args[2])
	}
	return cmd, nil
}

func ParseOperNickCommand(args []string) (Command, error) {
	return &OperNickCommand{
		target: NewName(args[0]),
		nick:   NewName(args[1]),
	}, nil
}
*/
