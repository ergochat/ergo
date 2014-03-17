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
		AWAY:    NewAwayCommand,
		CAP:     NewCapCommand,
		DEBUG:   NewDebugCommand,
		INVITE:  NewInviteCommand,
		ISON:    NewIsOnCommand,
		JOIN:    NewJoinCommand,
		KICK:    NewKickCommand,
		KILL:    NewKillCommand,
		LIST:    NewListCommand,
		MODE:    NewModeCommand,
		MOTD:    NewMOTDCommand,
		NAMES:   NewNamesCommand,
		NICK:    NewNickCommand,
		NOTICE:  NewNoticeCommand,
		ONICK:   NewOperNickCommand,
		OPER:    NewOperCommand,
		PART:    NewPartCommand,
		PASS:    NewPassCommand,
		PING:    NewPingCommand,
		PONG:    NewPongCommand,
		PRIVMSG: NewPrivMsgCommand,
		PROXY:   NewProxyCommand,
		QUIT:    NewQuitCommand,
		TIME:    NewTimeCommand,
		TOPIC:   NewTopicCommand,
		USER:    NewUserCommand,
		VERSION: NewVersionCommand,
		WHO:     NewWhoCommand,
		WHOIS:   NewWhoisCommand,
		WHOWAS:  NewWhoWasCommand,
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

func ParseCommand(line string) (cmd Command, err error) {
	code, args := ParseLine(line)
	constructor := parseCommandFuncs[code]
	if constructor == nil {
		cmd = NewUnknownCommand(args)
	} else {
		cmd, err = constructor(args)
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

func (cmd *UnknownCommand) String() string {
	return fmt.Sprintf("UNKNOWN(command=%s, args=%s)", cmd.Code(), cmd.args)
}

func NewUnknownCommand(args []string) *UnknownCommand {
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

func (cmd *PingCommand) String() string {
	return fmt.Sprintf("PING(server=%s, server2=%s)", cmd.server, cmd.server2)
}

func NewPingCommand(args []string) (Command, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
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

func (cmd *PongCommand) String() string {
	return fmt.Sprintf("PONG(server1=%s, server2=%s)", cmd.server1, cmd.server2)
}

func NewPongCommand(args []string) (Command, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
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

func (cmd *PassCommand) String() string {
	return fmt.Sprintf("PASS(password=%s)", cmd.password)
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

func NewPassCommand(args []string) (Command, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	return &PassCommand{
		password: []byte(args[0]),
	}, nil
}

// NICK <nickname>

func NewNickCommand(args []string) (Command, error) {
	if len(args) != 1 {
		return nil, NotEnoughArgsError
	}
	return &NickCommand{
		nickname: NewName(args[0]),
	}, nil
}

type UserCommand struct {
	BaseCommand
	username Name
	realname Text
}

// USER <username> <hostname> <servername> <realname>
type RFC1459UserCommand struct {
	UserCommand
	hostname   Name
	servername Name
}

func (cmd *RFC1459UserCommand) String() string {
	return fmt.Sprintf("USER(username=%s, hostname=%s, servername=%s, realname=%s)",
		cmd.username, cmd.hostname, cmd.servername, cmd.realname)
}

// USER <user> <mode> <unused> <realname>
type RFC2812UserCommand struct {
	UserCommand
	mode   uint8
	unused string
}

func (cmd *RFC2812UserCommand) String() string {
	return fmt.Sprintf("USER(username=%s, mode=%d, unused=%s, realname=%s)",
		cmd.username, cmd.mode, cmd.unused, cmd.realname)
}

func (cmd *RFC2812UserCommand) Flags() []UserMode {
	flags := make([]UserMode, 0)
	if (cmd.mode & 4) == 4 {
		flags = append(flags, WallOps)
	}
	if (cmd.mode & 8) == 8 {
		flags = append(flags, Invisible)
	}
	return flags
}

func NewUserCommand(args []string) (Command, error) {
	if len(args) != 4 {
		return nil, NotEnoughArgsError
	}
	mode, err := strconv.ParseUint(args[1], 10, 8)
	if err == nil {
		msg := &RFC2812UserCommand{
			mode:   uint8(mode),
			unused: args[2],
		}
		msg.username = NewName(args[0])
		msg.realname = NewText(args[3])
		return msg, nil
	}

	msg := &RFC1459UserCommand{
		hostname:   NewName(args[1]),
		servername: NewName(args[2]),
	}
	msg.username = NewName(args[0])
	msg.realname = NewText(args[3])
	return msg, nil
}

// QUIT [ <Quit Command> ]

type QuitCommand struct {
	BaseCommand
	message Text
}

func (cmd *QuitCommand) String() string {
	return fmt.Sprintf("QUIT(message=%s)", cmd.message)
}

func NewQuitCommand(args []string) (Command, error) {
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

func (cmd *JoinCommand) String() string {
	return fmt.Sprintf("JOIN(channels=%s, zero=%t)", cmd.channels, cmd.zero)
}

func NewJoinCommand(args []string) (Command, error) {
	msg := &JoinCommand{
		channels: make(map[Name]Text),
	}

	if len(args) == 0 {
		return nil, NotEnoughArgsError
	}

	if args[0] == "0" {
		msg.zero = true
		return msg, nil
	}

	channels := strings.Split(args[0], ",")
	keys := make([]string, len(channels))
	if len(args) > 1 {
		for i, key := range strings.Split(args[1], ",") {
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

func (cmd *PartCommand) String() string {
	return fmt.Sprintf("PART(channels=%s, message=%s)", cmd.channels, cmd.message)
}

func NewPartCommand(args []string) (Command, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
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

func (cmd *PrivMsgCommand) String() string {
	return fmt.Sprintf("PRIVMSG(target=%s, message=%s)", cmd.target, cmd.message)
}

func NewPrivMsgCommand(args []string) (Command, error) {
	if len(args) < 2 {
		return nil, NotEnoughArgsError
	}
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

func (cmd *TopicCommand) String() string {
	return fmt.Sprintf("TOPIC(channel=%s, topic=%s)", cmd.channel, cmd.topic)
}

func NewTopicCommand(args []string) (Command, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
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
		if change.op == op {
			str += change.mode.String()
		} else {
			op = change.op
			str += " " + change.op.String()
		}
	}
	return str
}

type ModeCommand struct {
	BaseCommand
	nickname Name
	changes  ModeChanges
}

// MODE <nickname> *( ( "+" / "-" ) *( "i" / "w" / "o" / "O" / "r" ) )
func NewUserModeCommand(nickname Name, args []string) (Command, error) {
	cmd := &ModeCommand{
		nickname: nickname,
		changes:  make(ModeChanges, 0),
	}

	for _, modeChange := range args {
		if len(modeChange) == 0 {
			continue
		}
		op := ModeOp(modeChange[0])
		if (op != Add) && (op != Remove) {
			return nil, ErrParseCommand
		}

		for _, mode := range modeChange[1:] {
			cmd.changes = append(cmd.changes, &ModeChange{
				mode: UserMode(mode),
				op:   op,
			})
		}
	}

	return cmd, nil
}

func (cmd *ModeCommand) String() string {
	return fmt.Sprintf("MODE(nickname=%s, changes=%s)", cmd.nickname, cmd.changes)
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

func (changes ChannelModeChanges) String() (str string) {
	if len(changes) == 0 {
		return
	}

	str = "+"
	if changes[0].op == Remove {
		str = "-"
	}
	for _, change := range changes {
		str += change.mode.String()
	}
	for _, change := range changes {
		if change.arg == "" {
			continue
		}
		str += " " + change.arg
	}
	return
}

type ChannelModeCommand struct {
	BaseCommand
	channel Name
	changes ChannelModeChanges
}

// MODE <channel> *( ( "-" / "+" ) *<modes> *<modeparams> )
func NewChannelModeCommand(channel Name, args []string) (Command, error) {
	cmd := &ChannelModeCommand{
		channel: channel,
		changes: make(ChannelModeChanges, 0),
	}

	for len(args) > 0 {
		if len(args[0]) == 0 {
			args = args[1:]
			continue
		}

		modeArg := args[0]
		op := ModeOp(modeArg[0])
		if (op == Add) || (op == Remove) {
			modeArg = modeArg[1:]
		} else {
			op = List
		}

		skipArgs := 1
		for _, mode := range modeArg {
			change := &ChannelModeChange{
				mode: ChannelMode(mode),
				op:   op,
			}
			switch change.mode {
			case Key, BanMask, ExceptMask, InviteMask, UserLimit,
				ChannelOperator, ChannelCreator, Voice:
				if len(args) > skipArgs {
					change.arg = args[skipArgs]
					skipArgs += 1
				}
			}
			cmd.changes = append(cmd.changes, change)
		}
		args = args[skipArgs:]
	}

	return cmd, nil
}

func (msg *ChannelModeCommand) String() string {
	return fmt.Sprintf("MODE(channel=%s, changes=%s)", msg.channel, msg.changes)
}

func NewModeCommand(args []string) (Command, error) {
	if len(args) == 0 {
		return nil, NotEnoughArgsError
	}

	name := NewName(args[0])
	if name.IsChannel() {
		return NewChannelModeCommand(name, args[1:])
	} else {
		return NewUserModeCommand(name, args[1:])
	}
}

type WhoisCommand struct {
	BaseCommand
	target Name
	masks  []Name
}

// WHOIS [ <target> ] <mask> *( "," <mask> )
func NewWhoisCommand(args []string) (Command, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}

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

func (msg *WhoisCommand) String() string {
	return fmt.Sprintf("WHOIS(target=%s, masks=%s)", msg.target, msg.masks)
}

type WhoCommand struct {
	BaseCommand
	mask         Name
	operatorOnly bool
}

// WHO [ <mask> [ "o" ] ]
func NewWhoCommand(args []string) (Command, error) {
	cmd := &WhoCommand{}

	if len(args) > 0 {
		cmd.mask = NewName(args[0])
	}

	if (len(args) > 1) && (args[1] == "o") {
		cmd.operatorOnly = true
	}

	return cmd, nil
}

func (msg *WhoCommand) String() string {
	return fmt.Sprintf("WHO(mask=%s, operatorOnly=%t)", msg.mask, msg.operatorOnly)
}

type OperCommand struct {
	PassCommand
	name Name
}

func (msg *OperCommand) String() string {
	return fmt.Sprintf("OPER(name=%s, password=%s)", msg.name, msg.password)
}

func (msg *OperCommand) LoadPassword(server *Server) {
	msg.hash = server.operators[msg.name]
}

// OPER <name> <password>
func NewOperCommand(args []string) (Command, error) {
	if len(args) < 2 {
		return nil, NotEnoughArgsError
	}

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

func (msg *CapCommand) String() string {
	return fmt.Sprintf("CAP(subCommand=%s, capabilities=%s)",
		msg.subCommand, msg.capabilities)
}

func NewCapCommand(args []string) (Command, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}

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

func (msg *ProxyCommand) String() string {
	return fmt.Sprintf("PROXY(sourceIP=%s, sourcePort=%s)", msg.sourceIP, msg.sourcePort)
}

func NewProxyCommand(args []string) (Command, error) {
	if len(args) < 5 {
		return nil, NotEnoughArgsError
	}
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
	away bool
}

func (msg *AwayCommand) String() string {
	return fmt.Sprintf("AWAY(%s)", msg.text)
}

func NewAwayCommand(args []string) (Command, error) {
	cmd := &AwayCommand{}

	if len(args) > 0 {
		cmd.text = NewText(args[0])
		cmd.away = true
	}

	return cmd, nil
}

type IsOnCommand struct {
	BaseCommand
	nicks []Name
}

func (msg *IsOnCommand) String() string {
	return fmt.Sprintf("ISON(nicks=%s)", msg.nicks)
}

func NewIsOnCommand(args []string) (Command, error) {
	if len(args) == 0 {
		return nil, NotEnoughArgsError
	}

	return &IsOnCommand{
		nicks: NewNames(args),
	}, nil
}

type MOTDCommand struct {
	BaseCommand
	target Name
}

func NewMOTDCommand(args []string) (Command, error) {
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

func (cmd *NoticeCommand) String() string {
	return fmt.Sprintf("NOTICE(target=%s, message=%s)", cmd.target, cmd.message)
}

func NewNoticeCommand(args []string) (Command, error) {
	if len(args) < 2 {
		return nil, NotEnoughArgsError
	}
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

func NewKickCommand(args []string) (Command, error) {
	if len(args) < 2 {
		return nil, NotEnoughArgsError
	}
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

func NewListCommand(args []string) (Command, error) {
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

func NewNamesCommand(args []string) (Command, error) {
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

func NewDebugCommand(args []string) (Command, error) {
	if len(args) == 0 {
		return nil, NotEnoughArgsError
	}

	return &DebugCommand{
		subCommand: NewName(strings.ToUpper(args[0])),
	}, nil
}

type VersionCommand struct {
	BaseCommand
	target Name
}

func NewVersionCommand(args []string) (Command, error) {
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

func NewInviteCommand(args []string) (Command, error) {
	if len(args) < 2 {
		return nil, NotEnoughArgsError
	}

	return &InviteCommand{
		nickname: NewName(args[0]),
		channel:  NewName(args[1]),
	}, nil
}

type TimeCommand struct {
	BaseCommand
	target Name
}

func NewTimeCommand(args []string) (Command, error) {
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

func NewKillCommand(args []string) (Command, error) {
	if len(args) < 2 {
		return nil, NotEnoughArgsError
	}
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

func NewWhoWasCommand(args []string) (Command, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
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

func NewOperNickCommand(args []string) (Command, error) {
	if len(args) < 2 {
		return nil, NotEnoughArgsError
	}

	return &OperNickCommand{
		target: NewName(args[0]),
		nick:   NewName(args[1]),
	}, nil
}
