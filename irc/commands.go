package irc

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type editableCommand interface {
	Command
	SetCode(StringCode)
	SetClient(*Client)
}

type parseCommandFunc func([]string) (editableCommand, error)

var (
	NotEnoughArgsError = errors.New("not enough arguments")
	ErrParseCommand    = errors.New("failed to parse message")
	parseCommandFuncs  = map[StringCode]parseCommandFunc{
		AWAY:    NewAwayCommand,
		CAP:     NewCapCommand,
		ISON:    NewIsOnCommand,
		JOIN:    NewJoinCommand,
		KICK:    NewKickCommand,
		LIST:    NewListCommand,
		MODE:    NewModeCommand,
		MOTD:    NewMOTDCommand,
		NAMES:   NewNamesCommand,
		NICK:    NewNickCommand,
		NOTICE:  NewNoticeCommand,
		OPER:    NewOperCommand,
		PART:    NewPartCommand,
		PASS:    NewPassCommand,
		PING:    NewPingCommand,
		PONG:    NewPongCommand,
		PRIVMSG: NewPrivMsgCommand,
		PROXY:   NewProxyCommand,
		QUIT:    NewQuitCommand,
		TOPIC:   NewTopicCommand,
		USER:    NewUserCommand,
		WHO:     NewWhoCommand,
		WHOIS:   NewWhoisCommand,
	}
)

type BaseCommand struct {
	client *Client
	code   StringCode
}

func (command *BaseCommand) Client() *Client {
	return command.client
}

func (command *BaseCommand) SetClient(c *Client) {
	command.client = c
}

func (command *BaseCommand) Code() StringCode {
	return command.code
}

func (command *BaseCommand) SetCode(code StringCode) {
	command.code = code
}

func (command *BaseCommand) Source() Identifier {
	return command.Client()
}

func ParseCommand(line string) (cmd editableCommand, err error) {
	code, args := parseLine(line)
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

func parseArg(line string) (arg string, rest string) {
	if line == "" {
		return
	}

	if strings.HasPrefix(line, ":") {
		arg = line[1:]
	} else {
		parts := spacesExpr.Split(line, 2)
		arg = parts[0]
		if len(parts) > 1 {
			rest = parts[1]
		}
	}
	return
}

func parseLine(line string) (command StringCode, args []string) {
	args = make([]string, 0)
	for arg, rest := parseArg(line); arg != ""; arg, rest = parseArg(rest) {
		if arg == "" {
			continue
		}
		args = append(args, arg)
	}
	if len(args) > 0 {
		command, args = StringCode(strings.ToUpper(args[0])), args[1:]
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
	server  string
	server2 string
}

func (cmd *PingCommand) String() string {
	return fmt.Sprintf("PING(server=%s, server2=%s)", cmd.server, cmd.server2)
}

func NewPingCommand(args []string) (editableCommand, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	msg := &PingCommand{
		server: args[0],
	}
	if len(args) > 1 {
		msg.server2 = args[1]
	}
	return msg, nil
}

// PONG <server> [ <server2> ]

type PongCommand struct {
	BaseCommand
	server1 string
	server2 string
}

func (cmd *PongCommand) String() string {
	return fmt.Sprintf("PONG(server1=%s, server2=%s)", cmd.server1, cmd.server2)
}

func NewPongCommand(args []string) (editableCommand, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	message := &PongCommand{
		server1: args[0],
	}
	if len(args) > 1 {
		message.server2 = args[1]
	}
	return message, nil
}

// PASS <password>

type PassCommand struct {
	BaseCommand
	password string
}

func (cmd *PassCommand) String() string {
	return fmt.Sprintf("PASS(password=%s)", cmd.password)
}

func NewPassCommand(args []string) (editableCommand, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	return &PassCommand{
		password: args[0],
	}, nil
}

// NICK <nickname>

type NickCommand struct {
	BaseCommand
	nickname string
}

func (m *NickCommand) String() string {
	return fmt.Sprintf("NICK(nickname=%s)", m.nickname)
}

func NewNickCommand(args []string) (editableCommand, error) {
	if len(args) != 1 {
		return nil, NotEnoughArgsError
	}
	return &NickCommand{
		nickname: args[0],
	}, nil
}

type UserCommand struct {
	BaseCommand
	username string
	realname string
}

// USER <username> <hostname> <servername> <realname>
type RFC1459UserCommand struct {
	UserCommand
	hostname   string
	servername string
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

func NewUserCommand(args []string) (editableCommand, error) {
	if len(args) != 4 {
		return nil, NotEnoughArgsError
	}
	mode, err := strconv.ParseUint(args[1], 10, 8)
	if err == nil {
		msg := &RFC2812UserCommand{
			mode:   uint8(mode),
			unused: args[2],
		}
		msg.username = args[0]
		msg.realname = args[3]
		return msg, nil
	}

	msg := &RFC1459UserCommand{
		hostname:   args[1],
		servername: args[2],
	}
	msg.username = args[0]
	msg.realname = args[3]
	return msg, nil
}

// QUIT [ <Quit Command> ]

type QuitCommand struct {
	BaseCommand
	message string
}

func (cmd *QuitCommand) String() string {
	return fmt.Sprintf("QUIT(message=%s)", cmd.message)
}

func NewQuitCommand(args []string) (editableCommand, error) {
	msg := &QuitCommand{}
	if len(args) > 0 {
		msg.message = args[0]
	}
	return msg, nil
}

// JOIN ( <channel> *( "," <channel> ) [ <key> *( "," <key> ) ] ) / "0"

type JoinCommand struct {
	BaseCommand
	channels map[string]string
	zero     bool
}

func (cmd *JoinCommand) String() string {
	return fmt.Sprintf("JOIN(channels=%s, zero=%t)", cmd.channels, cmd.zero)
}

func NewJoinCommand(args []string) (editableCommand, error) {
	msg := &JoinCommand{
		channels: make(map[string]string),
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
		msg.channels[channel] = keys[i]
	}

	return msg, nil
}

// PART <channel> *( "," <channel> ) [ <Part Command> ]

type PartCommand struct {
	BaseCommand
	channels []string
	message  string
}

func (cmd *PartCommand) Message() string {
	if cmd.message == "" {
		return cmd.Source().Nick()
	}
	return cmd.message
}

func (cmd *PartCommand) String() string {
	return fmt.Sprintf("PART(channels=%s, message=%s)", cmd.channels, cmd.message)
}

func NewPartCommand(args []string) (editableCommand, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	msg := &PartCommand{
		channels: strings.Split(args[0], ","),
	}
	if len(args) > 1 {
		msg.message = args[1]
	}
	return msg, nil
}

// PRIVMSG <target> <message>

type PrivMsgCommand struct {
	BaseCommand
	target  string
	message string
}

func (cmd *PrivMsgCommand) String() string {
	return fmt.Sprintf("PRIVMSG(target=%s, message=%s)", cmd.target, cmd.message)
}

func NewPrivMsgCommand(args []string) (editableCommand, error) {
	if len(args) < 2 {
		return nil, NotEnoughArgsError
	}
	return &PrivMsgCommand{
		target:  args[0],
		message: args[1],
	}, nil
}

// TOPIC [newtopic]

type TopicCommand struct {
	BaseCommand
	channel  string
	setTopic bool
	topic    string
}

func (cmd *TopicCommand) String() string {
	return fmt.Sprintf("TOPIC(channel=%s, topic=%s)", cmd.channel, cmd.topic)
}

func NewTopicCommand(args []string) (editableCommand, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	msg := &TopicCommand{
		channel: args[0],
	}
	if len(args) > 1 {
		msg.setTopic = true
		msg.topic = args[1]
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

type ModeChanges []ModeChange

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
	nickname string
	changes  ModeChanges
}

// MODE <nickname> *( ( "+" / "-" ) *( "i" / "w" / "o" / "O" / "r" ) )
func NewUserModeCommand(args []string) (editableCommand, error) {
	cmd := &ModeCommand{
		nickname: args[0],
		changes:  make(ModeChanges, 0),
	}

	for _, modeChange := range args[1:] {
		op := ModeOp(modeChange[0])
		if (op != Add) && (op != Remove) {
			return nil, ErrParseCommand
		}

		for _, mode := range modeChange[1:] {
			cmd.changes = append(cmd.changes, ModeChange{
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

type ChannelModeChanges []ChannelModeChange

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
	channel string
	changes ChannelModeChanges
}

// MODE <channel> *( ( "-" / "+" ) *<modes> *<modeparams> )
func NewChannelModeCommand(args []string) (editableCommand, error) {
	cmd := &ChannelModeCommand{
		channel: args[0],
		changes: make(ChannelModeChanges, 0),
	}
	args = args[1:]

	for len(args) > 0 {
		modeArg := args[0]

		op := ModeOp(modeArg[0])
		if (op == Add) || (op == Remove) {
			modeArg = modeArg[1:]
		} else {
			op = List
		}

		skipArgs := 1
		for _, mode := range modeArg {
			change := ChannelModeChange{
				mode: ChannelMode(mode),
				op:   op,
			}
			switch change.mode {
			case Key, BanMask, ExceptionMask, InviteMask, UserLimit,
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

func NewModeCommand(args []string) (editableCommand, error) {
	if len(args) == 0 {
		return nil, NotEnoughArgsError
	}

	if IsChannel(args[0]) {
		return NewChannelModeCommand(args)
	} else {
		return NewUserModeCommand(args)
	}
}

type WhoisCommand struct {
	BaseCommand
	target string
	masks  []string
}

// WHOIS [ <target> ] <mask> *( "," <mask> )
func NewWhoisCommand(args []string) (editableCommand, error) {
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
		target: target,
		masks:  strings.Split(masks, ","),
	}, nil
}

func (msg *WhoisCommand) String() string {
	return fmt.Sprintf("WHOIS(target=%s, masks=%s)", msg.target, msg.masks)
}

type WhoCommand struct {
	BaseCommand
	mask         Mask
	operatorOnly bool
}

// WHO [ <mask> [ "o" ] ]
func NewWhoCommand(args []string) (editableCommand, error) {
	cmd := &WhoCommand{}

	if len(args) > 0 {
		cmd.mask = Mask(args[0])
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
	BaseCommand
	name     string
	password string
}

func (msg *OperCommand) String() string {
	return fmt.Sprintf("OPER(name=%s, password=%s)", msg.name, msg.password)
}

// OPER <name> <password>
func NewOperCommand(args []string) (editableCommand, error) {
	if len(args) < 2 {
		return nil, NotEnoughArgsError
	}

	return &OperCommand{
		name:     args[0],
		password: args[1],
	}, nil
}

// TODO
type CapCommand struct {
	BaseCommand
	args []string
}

func (msg *CapCommand) String() string {
	return fmt.Sprintf("CAP(args=%s)", msg.args)
}

func NewCapCommand(args []string) (editableCommand, error) {
	return &CapCommand{
		args: args,
	}, nil
}

// HAPROXY support
type ProxyCommand struct {
	BaseCommand
	net        string
	sourceIP   string
	destIP     string
	sourcePort string
	destPort   string
}

func (msg *ProxyCommand) String() string {
	return fmt.Sprintf("PROXY(sourceIP=%s, sourcePort=%s)", msg.sourceIP, msg.sourcePort)
}

func NewProxyCommand(args []string) (editableCommand, error) {
	if len(args) < 5 {
		return nil, NotEnoughArgsError
	}
	return &ProxyCommand{
		net:        args[0],
		sourceIP:   args[1],
		destIP:     args[2],
		sourcePort: args[3],
		destPort:   args[4],
	}, nil
}

type AwayCommand struct {
	BaseCommand
	text string
	away bool
}

func (msg *AwayCommand) String() string {
	return fmt.Sprintf("AWAY(%s)", msg.text)
}

func NewAwayCommand(args []string) (editableCommand, error) {
	cmd := &AwayCommand{}

	if len(args) > 0 {
		cmd.text = args[0]
		cmd.away = true
	}

	return cmd, nil
}

type IsOnCommand struct {
	BaseCommand
	nicks []string
}

func (msg *IsOnCommand) String() string {
	return fmt.Sprintf("ISON(nicks=%s)", msg.nicks)
}

func NewIsOnCommand(args []string) (editableCommand, error) {
	if len(args) == 0 {
		return nil, NotEnoughArgsError
	}

	return &IsOnCommand{
		nicks: args,
	}, nil
}

type MOTDCommand struct {
	BaseCommand
	target string
}

func NewMOTDCommand(args []string) (editableCommand, error) {
	cmd := &MOTDCommand{}
	if len(args) > 0 {
		cmd.target = args[0]
	}
	return cmd, nil
}

type NoticeCommand struct {
	BaseCommand
	target  string
	message string
}

func (cmd *NoticeCommand) String() string {
	return fmt.Sprintf("NOTICE(target=%s, message=%s)", cmd.target, cmd.message)
}

func NewNoticeCommand(args []string) (editableCommand, error) {
	if len(args) < 2 {
		return nil, NotEnoughArgsError
	}
	return &NoticeCommand{
		target:  args[0],
		message: args[1],
	}, nil
}

type KickCommand struct {
	BaseCommand
	kicks   map[string]string
	comment string
}

func (msg *KickCommand) Comment() string {
	if msg.comment == "" {
		return msg.Source().Nick()
	}
	return msg.comment
}

func NewKickCommand(args []string) (editableCommand, error) {
	if len(args) < 2 {
		return nil, NotEnoughArgsError
	}
	channels := strings.Split(args[0], ",")
	users := strings.Split(args[1], ",")
	if (len(channels) != len(users)) && (len(users) != 1) {
		return nil, NotEnoughArgsError
	}
	cmd := &KickCommand{
		kicks: make(map[string]string),
	}
	for index, channel := range channels {
		if len(users) == 1 {
			cmd.kicks[channel] = users[0]
		} else {
			cmd.kicks[channel] = users[index]
		}
	}
	if len(args) > 2 {
		cmd.comment = args[2]
	}
	return cmd, nil
}

type ListCommand struct {
	BaseCommand
	channels []string
	target   string
}

func NewListCommand(args []string) (editableCommand, error) {
	cmd := &ListCommand{}
	if len(args) > 0 {
		cmd.channels = strings.Split(args[0], ",")
	}
	if len(args) > 1 {
		cmd.target = args[1]
	}
	return cmd, nil
}

type NamesCommand struct {
	BaseCommand
	channels []string
	target   string
}

func NewNamesCommand(args []string) (editableCommand, error) {
	cmd := &NamesCommand{}
	if len(args) > 0 {
		cmd.channels = strings.Split(args[0], ",")
	}
	if len(args) > 1 {
		cmd.target = args[1]
	}
	return cmd, nil
}
