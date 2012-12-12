package irc

import (
	"errors"
	"strings"
)

type ParseFunc func([]string) (Message, error)

var (
	ErrParseMessage   = errors.New("failed to parse message")
	parseCommandFuncs = map[string]ParseFunc{
		"JOIN":    NewJoinMessage,
		"MODE":    NewModeMessage,
		"NICK":    NewNickMessage,
		"PART":    NewPartMessage,
		"PASS":    NewPassMessage,
		"PING":    NewPingMessage,
		"PONG":    NewPongMessage,
		"PRIVMSG": NewPrivMsgMessage,
		"QUIT":    NewQuitMessage,
		"TOPIC":   NewTopicMessage,
		"USER":    NewUserMessage,
		"OPER":    NewOperMessage,
	}
)

func ParseMessage(line string) (Message, error) {
	command, args := parseLine(line)
	constructor, ok := parseCommandFuncs[command]
	if !ok {
		return &UnknownMessage{command, args}, nil
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
	command, args = args[0], args[1:]
	return
}
