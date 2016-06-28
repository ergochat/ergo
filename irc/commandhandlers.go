// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

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
