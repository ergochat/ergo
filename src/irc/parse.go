package irc

import (
	"errors"
	"strings"
)

type ParseFunc func([]string) (Command, error)

var (
	ErrParseCommand   = errors.New("failed to parse message")
	parseCommandFuncs = map[string]ParseFunc{
		"JOIN":    NewJoinCommand,
		"LOGIN":   NewLoginCommand,
		"NICK":    NewNickCommand,
		"PART":    NewPartCommand,
		"PASS":    NewPassCommand,
		"PING":    NewPingCommand,
		"PONG":    NewPongCommand,
		"PRIVMSG": NewPrivMsgCommand,
		"QUIT":    NewQuitCommand,
		"TOPIC":   NewTopicCommand,
		"USER":    NewUserCommand,
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
	command, args = args[0], args[1:]
	return
}
