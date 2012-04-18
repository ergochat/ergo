package irc

import (
	"fmt"
)

func ReplyWelcome(nick string, user string, host string) string {
	return fmt.Sprintf("%s %s Welcome to the Internet Relay Network %s!%s@%s", RPL_WELCOME, nick, nick, user, host)
}

func ReplyYourHost(nick string, server string) string {
	return fmt.Sprintf("%s %s Your host is %s, running version %s", RPL_YOURHOST, nick, server, VERSION)
}

func ReplyCreated(nick string, created string) string {
	return fmt.Sprintf("%s %s This server was created %s", RPL_CREATED, nick, created)
}

func ReplyMyInfo(nick string, servername string) string {
	return fmt.Sprintf("%s %s %s %s <user modes> <channel modes>", RPL_MYINFO, nick, servername, VERSION)
}

func ErrAlreadyRegistered(nick string) string {
	return fmt.Sprintf("%s %s :You may not reregister", ERR_ALREADYREGISTRED, nick)
}

func ErrNickNameInUse(nick string) string {
	return fmt.Sprintf("%s %s :Nickname is already in use", ERR_NICKNAMEINUSE, nick)
}

func ErrUnknownCommand(nick string, command string) string {
	return fmt.Sprintf("%s %s %s :Unknown command", ERR_UNKNOWNCOMMAND, nick, command)
}

func MessagePong() string {
	return "PONG"
}

func MessageError() string {
	return "ERROR :Bye"
}
