package irc

import (
	"errors"
	"strconv"
	"strings"
)

var (
	NotEnoughArgsError = errors.New("not enough arguments")
)

type BaseCommand struct {
	client *Client
}

func (base *BaseCommand) Client() *Client {
	return base.client
}

func (base *BaseCommand) SetClient(c *Client) {
	base.client = c
}

var (
	ErrParseCommand   = errors.New("failed to parse message")
	parseCommandFuncs = map[string]func([]string) (Command, error){
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

func ParseCommand(line string) (Command, error) {
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
	*BaseCommand
	command string
	args    []string
}

func NewUnknownCommand(command string, args []string) *UnknownCommand {
	return &UnknownCommand{
		BaseCommand: &BaseCommand{},
		command:     command,
		args:        args,
	}
}

// PING <server1> [ <server2> ]

type PingCommand struct {
	*BaseCommand
	server  string
	server2 string
}

func NewPingCommand(args []string) (Command, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	msg := &PingCommand{
		BaseCommand: &BaseCommand{},
		server:      args[0],
	}
	if len(args) > 1 {
		msg.server2 = args[1]
	}
	return msg, nil
}

// PONG <server> [ <server2> ]

type PongCommand struct {
	*BaseCommand
	server1 string
	server2 string
}

func NewPongCommand(args []string) (Command, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	message := &PongCommand{
		BaseCommand: &BaseCommand{},
		server1:     args[0],
	}
	if len(args) > 1 {
		message.server2 = args[1]
	}
	return message, nil
}

// PASS <password>

type PassCommand struct {
	*BaseCommand
	password string
}

func NewPassCommand(args []string) (Command, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	return &PassCommand{
		BaseCommand: &BaseCommand{},
		password:    args[0],
	}, nil
}

// NICK <nickname>

type NickCommand struct {
	*BaseCommand
	nickname string
}

func NewNickCommand(args []string) (Command, error) {
	if len(args) != 1 {
		return nil, NotEnoughArgsError
	}
	return &NickCommand{
		BaseCommand: &BaseCommand{},
		nickname:    args[0],
	}, nil
}

// USER <user> <mode> <unused> <realname>

type UserMsgCommand struct {
	*BaseCommand
	user     string
	mode     uint8
	unused   string
	realname string
}

func NewUserMsgCommand(args []string) (Command, error) {
	if len(args) != 4 {
		return nil, NotEnoughArgsError
	}
	msg := &UserMsgCommand{
		BaseCommand: &BaseCommand{},
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
	*BaseCommand
	message string
}

func NewQuitCommand(args []string) (Command, error) {
	msg := &QuitCommand{
		BaseCommand: &BaseCommand{},
	}
	if len(args) > 0 {
		msg.message = args[0]
	}
	return msg, nil
}

// JOIN ( <channel> *( "," <channel> ) [ <key> *( "," <key> ) ] ) / "0"

type JoinCommand struct {
	*BaseCommand
	channels map[string]string
	zero     bool
}

func NewJoinCommand(args []string) (Command, error) {
	msg := &JoinCommand{
		BaseCommand: &BaseCommand{},
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
	*BaseCommand
	channels []string
	message  string
}

func NewPartCommand(args []string) (Command, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	msg := &PartCommand{
		BaseCommand: &BaseCommand{},
		channels:    strings.Split(args[0], ","),
	}
	if len(args) > 1 {
		msg.message = args[1]
	}
	return msg, nil
}

// PRIVMSG <target> <message>

type PrivMsgCommand struct {
	*BaseCommand
	target  string
	message string
}

func NewPrivMsgCommand(args []string) (Command, error) {
	if len(args) < 2 {
		return nil, NotEnoughArgsError
	}
	return &PrivMsgCommand{
		BaseCommand: &BaseCommand{},
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
	*BaseCommand
	channel string
	topic   string
}

func NewTopicCommand(args []string) (Command, error) {
	if len(args) < 1 {
		return nil, NotEnoughArgsError
	}
	msg := &TopicCommand{
		BaseCommand: &BaseCommand{},
		channel:     args[0],
	}
	if len(args) > 1 {
		msg.topic = args[1]
	}
	return msg, nil
}

type ModeCommand struct {
	*BaseCommand
	nickname string
	modes    string
}

func NewModeCommand(args []string) (Command, error) {
	if len(args) == 0 {
		return nil, NotEnoughArgsError
	}

	cmd := &ModeCommand{
		BaseCommand: &BaseCommand{},
		nickname:    args[0],
	}

	if len(args) > 1 {
		cmd.modes = args[1]
	}

	return cmd, nil
}
