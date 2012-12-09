package irc

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var commands = map[string]func([]string) Message{
	"JOIN":    NewJoinMessage,
	"MODE":    NewModeMessage,
	"NICK":    NewNickMessage,
	"PART":    NewPartMessage,
	"PING":    NewPingMessage,
	"PONG":    NewPongMessage,
	"PRIVMSG": NewPrivMsgMessage,
	"QUIT":    NewQuitMessage,
	"TOPIC":   NewTopicMessage,
	"USER":    NewUserMessage,
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

// []string => Message constructors

func NewNickMessage(args []string) Message {
	if len(args) != 1 {
		return nil
	}
	return &NickMessage{args[0]}
}

func NewPingMessage(args []string) Message {
	if len(args) < 1 {
		return nil
	}
	message := &PingMessage{server: args[0]}
	if len(args) > 1 {
		message.server2 = args[1]
	}
	return message
}

func NewPongMessage(args []string) Message {
	if len(args) < 1 {
		return nil
	}
	message := &PongMessage{server1: args[0]}
	if len(args) > 1 {
		message.server2 = args[1]
	}
	return message
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

var MODE_RE = regexp.MustCompile("^[-+][a-zA-Z]+$")

func NewModeMessage(args []string) Message {
	if len(args) < 1 {
		return nil
	}
	msg := new(ModeMessage)
	msg.nickname = args[0]
	for _, arg := range args[1:] {
		if !MODE_RE.MatchString(arg) {
			// TODO invalid args
			return nil
		}
		prefix := arg[0]
		for _, c := range arg[1:] {
			mode := fmt.Sprintf("%c%c", prefix, c)
			msg.modes = append(msg.modes, mode)
		}
	}
	return msg
}

func NewJoinMessage(args []string) Message {
	msg := new(JoinMessage)

	if len(args) > 0 {
		if args[0] == "0" {
			msg.zero = true
		} else {
			msg.channels = strings.Split(args[0], ",")
		}

		if len(args) > 1 {
			msg.keys = strings.Split(args[1], ",")
		}
	}

	return msg
}

func NewPartMessage(args []string) Message {
	if len(args) < 1 {
		return nil
	}
	msg := new(PartMessage)
	msg.channels = strings.Split(args[0], ",")

	if len(args) > 1 {
		msg.message = args[1]
	}

	return msg
}

func NewPrivMsgMessage(args []string) Message {
	if len(args) < 2 {
		return nil
	}

	return &PrivMsgMessage{target: args[0], message: args[1]}
}

func NewTopicMessage(args []string) Message {
	if len(args) < 1 {
		return nil
	}

	message := &TopicMessage{channel: args[0]}
	if len(args) > 1 {
		message.topic = args[1]
	}
	return message
}
