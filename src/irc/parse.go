package irc

import (
	"strconv"
	"strings"
)

func parseArg(line string) (string, string) {
	if line == "" {
		return "", ""
	}

	if strings.HasPrefix(line, ":") {
		return line[1:], ""
	}

	parts := strings.SplitN(line, " ", 2)
	arg := parts[0]
	rest := ""
	if len(parts) > 1 {
		rest = parts[1]
	}
	return arg, rest
}

func parseLine(line string) (string, []string) {
	args := make([]string, 0)
	for arg, rest := parseArg(line); arg != ""; arg, rest = parseArg(rest) {
		args = append(args, arg)
	}
	return args[0], args[1:]
}

var commands = map[string]func([]string) Message {
	"NICK": NewNickMessage,
	"PING": NewPingMessage,
	"QUIT": NewQuitMessage,
	"USER": NewUserMessage,
}

func ParseMessage(line string) Message {
	command, args := parseLine(line)
	constructor, ok := commands[command]
	var msg Message
	if ok {
		msg = constructor(args)
	}
	if msg == nil {
		msg = &UnknownMessage{command}
	}
	return msg
}

// []string => Message constructors

func NewNickMessage(args []string) Message {
	if len(args) != 1 {
		return nil
	}
	return &NickMessage{args[0]}
}

func NewPingMessage(args []string) Message {
	return &PingMessage{}
}

func NewQuitMessage(args []string) Message {
	msg := QuitMessage{}
	if len(args) > 0 {
		msg.message = args[0]
	}
	return &msg
}

func NewUserMessage(args []string) Message {
	if len(args) != 4 {
		return nil
	}
	msg := new(UserMessage)
	msg.user = args[0]
	mode, err := strconv.ParseUint(args[1], 10, 8)
	if err == nil {
		msg.mode = uint8(mode)
	}
	msg.unused = args[2]
	msg.realname = args[3]
	return msg
}
