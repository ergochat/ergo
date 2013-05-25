package irc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Command interface {
	Client() *Client
	User() *User
	Source() Identifier
	HandleServer(*Server)
}

type EditableCommand interface {
	Command
	SetClient(*Client)
}

var (
	NotEnoughArgsError = errors.New("not enough arguments")
	ErrParseCommand    = errors.New("failed to parse message")
	parseCommandFuncs  = map[string]func([]string) (EditableCommand, error){
		"JOIN":    NewJoinCommand,
		"MODE":    NewModeCommand,
		"NICK":    NewNickCommand,
		"PART":    NewPartCommand,
		"PASS":    NewPassCommand,
		"PING":    NewPingCommand,
		"PONG":    NewPongCommand,
		"PRIVMSG": NewPrivMsgCommand,
		"QUIT":    NewQuitCommand,
		"TOPIC":   NewTopicCommand,
		"USER":    NewUserMsgCommand,
	}
)

type BaseCommand struct {
	client *Client
}

func (command *BaseCommand) Client() *Client {
	return command.client
}

func (command *BaseCommand) User() *User {
	if command.Client() == nil {
		return nil
	}
	return command.User()
}

func (command *BaseCommand) SetClient(c *Client) {
	*command = BaseCommand{c}
}

func (command *BaseCommand) Source() Identifier {
	client := command.Client()
	if client == nil {
		return nil
	}
	if client.user != nil {
		return client.user
	}
	return client
}

func ParseCommand(line string) (EditableCommand, error) {
	command, args := parseLine(line)
	constructor := parseCommandFuncs[command]
	if constructor == nil {
		return NewUnknownCommand(command, args), nil
	}
	return constructor(args)
}

func parseArg(line string) (arg string, rest string) {
	if line == "" {
		return
	}

	if strings.HasPrefix(line, ":") {
		arg = line[1:]
	} else {
		parts := strings.SplitN(line, " ", 2)
		arg = parts[0]
		if len(parts) > 1 {
			rest = parts[1]
		}
	}
	return
}

func parseLine(line string) (command string, args []string) {
	args = make([]string, 0)
	for arg, rest := parseArg(line); arg != ""; arg, rest = parseArg(rest) {
		args = append(args, arg)
	}
	command, args = strings.ToUpper(args[0]), args[1:]
	return
}

// <command> [args...]

type UnknownCommand struct {
	BaseCommand
	command string
	args    []string
}

func (cmd *UnknownCommand) String() string {
	return fmt.Sprintf("UNKNOWN(command=%s, args=%s)", cmd.command, cmd.args)
}

func NewUnknownCommand(command string, args []string) *UnknownCommand {
	return &UnknownCommand{
		BaseCommand: BaseCommand{},
		command:     command,
		args:        args,
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

func NewPingCommand(args []string) (EditableCommand, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	msg := &PingCommand{
		BaseCommand: BaseCommand{},
		server:      args[0],
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

func NewPongCommand(args []string) (EditableCommand, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	message := &PongCommand{
		BaseCommand: BaseCommand{},
		server1:     args[0],
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

func NewPassCommand(args []string) (EditableCommand, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	return &PassCommand{
		BaseCommand: BaseCommand{},
		password:    args[0],
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

func NewNickCommand(args []string) (EditableCommand, error) {
	if len(args) != 1 {
		return nil, NotEnoughArgsError
	}
	return &NickCommand{
		BaseCommand: BaseCommand{},
		nickname:    args[0],
	}, nil
}

// USER <user> <mode> <unused> <realname>

type UserMsgCommand struct {
	BaseCommand
	user     string
	mode     uint8
	unused   string
	realname string
}

func (cmd *UserMsgCommand) String() string {
	return fmt.Sprintf("USER(user=%s, mode=%o, unused=%s, realname=%s)",
		cmd.user, cmd.mode, cmd.unused, cmd.realname)
}

func NewUserMsgCommand(args []string) (EditableCommand, error) {
	if len(args) != 4 {
		return nil, NotEnoughArgsError
	}
	msg := &UserMsgCommand{
		BaseCommand: BaseCommand{},
		user:        args[0],
		unused:      args[2],
		realname:    args[3],
	}
	mode, err := strconv.ParseUint(args[1], 10, 8)
	if err == nil {
		msg.mode = uint8(mode)
	}
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

func NewQuitCommand(args []string) (EditableCommand, error) {
	msg := &QuitCommand{
		BaseCommand: BaseCommand{},
	}
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

func NewJoinCommand(args []string) (EditableCommand, error) {
	msg := &JoinCommand{
		BaseCommand: BaseCommand{},
		channels:    make(map[string]string),
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

func (cmd *PartCommand) String() string {
	return fmt.Sprintf("PART(channels=%s, message=%s)", cmd.channels, cmd.message)
}

func NewPartCommand(args []string) (EditableCommand, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	msg := &PartCommand{
		BaseCommand: BaseCommand{},
		channels:    strings.Split(args[0], ","),
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

func NewPrivMsgCommand(args []string) (EditableCommand, error) {
	if len(args) < 2 {
		return nil, NotEnoughArgsError
	}
	return &PrivMsgCommand{
		BaseCommand: BaseCommand{},
		target:      args[0],
		message:     args[1],
	}, nil
}

func (m *PrivMsgCommand) TargetIsChannel() bool {
	switch m.target[0] {
	case '&', '#', '+', '!':
		return true
	}
	return false
}

// TOPIC [newtopic]

type TopicCommand struct {
	BaseCommand
	channel string
	topic   string
}

func (cmd *TopicCommand) String() string {
	return fmt.Sprintf("TOPIC(channel=%s, topic=%s)", cmd.channel, cmd.topic)
}

func NewTopicCommand(args []string) (EditableCommand, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	msg := &TopicCommand{
		BaseCommand: BaseCommand{},
		channel:     args[0],
	}
	if len(args) > 1 {
		msg.topic = args[1]
	}
	return msg, nil
}

type ModeCommand struct {
	BaseCommand
	nickname string
	modes    string
}

func (cmd *ModeCommand) String() string {
	return fmt.Sprintf("MODE(nickname=%s, modes=%s)", cmd.nickname, cmd.modes)
}

func NewModeCommand(args []string) (EditableCommand, error) {
	if len(args) == 0 {
		return nil, NotEnoughArgsError
	}

	cmd := &ModeCommand{
		BaseCommand: BaseCommand{},
		nickname:    args[0],
	}

	if len(args) > 1 {
		cmd.modes = args[1]
	}

	return cmd, nil
}
