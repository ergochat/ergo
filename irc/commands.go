package irc

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Command interface {
	Client() *Client
	Code() StringCode
	SetClient(*Client)
	SetCode(StringCode)
}

type checkPasswordCommand interface {
	LoadPassword(*Server)
	CheckPassword()
}

type parseCommandFunc func([]string) (Command, error)

var (
	NotEnoughArgsError = errors.New("not enough arguments")
	ErrParseCommand    = errors.New("failed to parse message")
	parseCommandFuncs  = map[StringCode]parseCommandFunc{
		AWAY:    ParseAwayCommand,
		CAP:     ParseCapCommand,
		DEBUG:   ParseDebugCommand,
		INVITE:  ParseInviteCommand,
		ISON:    ParseIsOnCommand,
		JOIN:    ParseJoinCommand,
		KICK:    ParseKickCommand,
		KILL:    ParseKillCommand,
		LIST:    ParseListCommand,
		MODE:    ParseModeCommand,
		MOTD:    ParseMOTDCommand,
		NAMES:   ParseNamesCommand,
		NICK:    ParseNickCommand,
		NOTICE:  ParseNoticeCommand,
		ONICK:   ParseOperNickCommand,
		OPER:    ParseOperCommand,
		PART:    ParsePartCommand,
		PASS:    ParsePassCommand,
		PING:    ParsePingCommand,
		PONG:    ParsePongCommand,
		PRIVMSG: ParsePrivMsgCommand,
		PROXY:   ParseProxyCommand,
		QUIT:    ParseQuitCommand,
		THEATER: ParseTheaterCommand, // nonstandard
		TIME:    ParseTimeCommand,
		TOPIC:   ParseTopicCommand,
		USER:    ParseUserCommand,
		VERSION: ParseVersionCommand,
		WHO:     ParseWhoCommand,
		WHOIS:   ParseWhoisCommand,
		WHOWAS:  ParseWhoWasCommand,
	}
	commandMinimumArgs = map[StringCode]int{
		AWAY:    0,
		CAP:     1,
		DEBUG:   1,
		INVITE:  2,
		ISON:    1,
		JOIN:    1,
		KICK:    2,
		KILL:    2,
		LIST:    0,
		MODE:    1,
		MOTD:    0,
		NAMES:   0,
		NICK:    1,
		NOTICE:  2,
		ONICK:   2,
		OPER:    2,
		PART:    1,
		PASS:    1,
		PING:    1,
		PONG:    1,
		PRIVMSG: 2,
		PROXY:   5,
		QUIT:    0,
		THEATER: 1,
		TIME:    0,
		TOPIC:   1,
		USER:    4,
		VERSION: 0,
		WHO:     0,
		WHOIS:   1,
		WHOWAS:  1,
	}
)

type BaseCommand struct {
	client *Client
	code   StringCode
}

func (command *BaseCommand) Client() *Client {
	return command.client
}

func (command *BaseCommand) SetClient(client *Client) {
	command.client = client
}

func (command *BaseCommand) Code() StringCode {
	return command.code
}

func (command *BaseCommand) SetCode(code StringCode) {
	command.code = code
}

type NeedMoreParamsCommand struct {
	BaseCommand
	code StringCode
}

func ParseNeedMoreParams(code StringCode) *NeedMoreParamsCommand {
	return &NeedMoreParamsCommand{
		code: code,
	}
}

func ParseCommand(line string) (cmd Command, err error) {
	code, args := ParseLine(line)
	constructor := parseCommandFuncs[code]
	minArgs := commandMinimumArgs[code]
	if constructor == nil {
		cmd = ParseUnknownCommand(args)
	} else if len(args) < minArgs {
		cmd = ParseNeedMoreParams(code)
	} else {
		cmd, err = constructor(args)

		// if NotEnoughArgsError was returned in the command handler itself
		if err == NotEnoughArgsError {
			cmd = ParseNeedMoreParams(code)
			err = nil
		}
	}
	if cmd != nil {
		cmd.SetCode(code)
	}
	return
}

var (
	spacesExpr = regexp.MustCompile(` +`)
)

func splitArg(line string) (arg string, rest string) {
	parts := spacesExpr.Split(line, 2)
	if len(parts) > 0 {
		arg = parts[0]
	}
	if len(parts) > 1 {
		rest = parts[1]
	}
	return
}

func ParseLine(line string) (command StringCode, args []string) {
	args = make([]string, 0)
	if strings.HasPrefix(line, ":") {
		_, line = splitArg(line)
	}
	arg, line := splitArg(line)
	command = StringCode(NewName(strings.ToUpper(arg)))
	for len(line) > 0 {
		if strings.HasPrefix(line, ":") {
			args = append(args, line[len(":"):])
			break
		}
		arg, line = splitArg(line)
		args = append(args, arg)
	}
	return
}

// <command> [args...]

type UnknownCommand struct {
	BaseCommand
	args []string
}

func ParseUnknownCommand(args []string) *UnknownCommand {
	return &UnknownCommand{
		args: args,
	}
}

// PING <server1> [ <server2> ]

type PingCommand struct {
	BaseCommand
	server  Name
	server2 Name
}

func ParsePingCommand(args []string) (Command, error) {
	msg := &PingCommand{
		server: NewName(args[0]),
	}
	if len(args) > 1 {
		msg.server2 = NewName(args[1])
	}
	return msg, nil
}

// PONG <server> [ <server2> ]

type PongCommand struct {
	BaseCommand
	server1 Name
	server2 Name
}

func ParsePongCommand(args []string) (Command, error) {
	message := &PongCommand{
		server1: NewName(args[0]),
	}
	if len(args) > 1 {
		message.server2 = NewName(args[1])
	}
	return message, nil
}

// PASS <password>

type PassCommand struct {
	BaseCommand
	hash     []byte
	password []byte
	err      error
}

func (cmd *PassCommand) LoadPassword(server *Server) {
	cmd.hash = server.password
}

func (cmd *PassCommand) CheckPassword() {
	if cmd.hash == nil {
		return
	}
	cmd.err = ComparePassword(cmd.hash, cmd.password)
}

func ParsePassCommand(args []string) (Command, error) {
	return &PassCommand{
		password: []byte(args[0]),
	}, nil
}

// NICK <nickname>

func ParseNickCommand(args []string) (Command, error) {
	return &NickCommand{
		nickname: NewName(args[0]),
	}, nil
}

type UserCommand struct {
	BaseCommand
	username Name
	realname Text
}

func ParseUserCommand(args []string) (Command, error) {
	return &UserCommand{
		username: NewName(args[0]),
		realname: NewText(args[3]),
	}, nil
}

// QUIT [ <Quit Command> ]

type QuitCommand struct {
	BaseCommand
	message Text
}

func NewQuitCommand(message Text) *QuitCommand {
	cmd := &QuitCommand{
		message: message,
	}
	cmd.code = QUIT
	return cmd
}

func ParseQuitCommand(args []string) (Command, error) {
	msg := &QuitCommand{}
	if len(args) > 0 {
		msg.message = NewText(args[0])
	}
	return msg, nil
}

// JOIN ( <channel> *( "," <channel> ) [ <key> *( "," <key> ) ] ) / "0"

type JoinCommand struct {
	BaseCommand
	channels map[Name]Text
	zero     bool
}

func ParseJoinCommand(args []string) (Command, error) {
	msg := &JoinCommand{
		channels: make(map[Name]Text),
	}

	if args[0] == "0" {
		msg.zero = true
		return msg, nil
	}

	channels := strings.Split(args[0], ",")
	keys := make([]string, len(channels))
	if len(args) > 1 {
		for i, key := range strings.Split(args[1], ",") {
			if i >= len(channels) {
				break
			}
			keys[i] = key
		}
	}
	for i, channel := range channels {
		msg.channels[NewName(channel)] = NewText(keys[i])
	}

	return msg, nil
}

// PART <channel> *( "," <channel> ) [ <Part Command> ]

type PartCommand struct {
	BaseCommand
	channels []Name
	message  Text
}

func (cmd *PartCommand) Message() Text {
	if cmd.message == "" {
		return cmd.Client().Nick().Text()
	}
	return cmd.message
}

func ParsePartCommand(args []string) (Command, error) {
	msg := &PartCommand{
		channels: NewNames(strings.Split(args[0], ",")),
	}
	if len(args) > 1 {
		msg.message = NewText(args[1])
	}
	return msg, nil
}

// PRIVMSG <target> <message>

type PrivMsgCommand struct {
	BaseCommand
	target  Name
	message Text
}

func ParsePrivMsgCommand(args []string) (Command, error) {
	return &PrivMsgCommand{
		target:  NewName(args[0]),
		message: NewText(args[1]),
	}, nil
}

// TOPIC [newtopic]

type TopicCommand struct {
	BaseCommand
	channel  Name
	setTopic bool
	topic    Text
}

func ParseTopicCommand(args []string) (Command, error) {
	msg := &TopicCommand{
		channel: NewName(args[0]),
	}
	if len(args) > 1 {
		msg.setTopic = true
		msg.topic = NewText(args[1])
	}
	return msg, nil
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
	BaseCommand
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
