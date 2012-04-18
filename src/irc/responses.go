package irc

import (
	"fmt"
	"time"
)

func ReplyNick(oldNick string, c *Client) string {
	return fmt.Sprintf(":%s!%s@%s %s :%s", oldNick, c.username, c.Hostname(), RPL_NICK, c.Nick())
}

func ReplyWelcome(c *Client) string {
	return fmt.Sprintf("%s %s Welcome to the Internet Relay Network %s!%s@%s", RPL_WELCOME, c.Nick(), c.Nick(), c.username, c.Hostname())
}

func ReplyYourHost(nick string, server string) string {
	return fmt.Sprintf("%s %s Your host is %s, running version %s", RPL_YOURHOST, nick, server, VERSION)
}

func ReplyCreated(nick string, ctime time.Time) string {
	return fmt.Sprintf("%s %s This server was created %s", RPL_CREATED, nick, ctime.Format(time.RFC1123))
}

func ReplyMyInfo(nick string, servername string) string {
	return fmt.Sprintf("%s %s %s %s i <channel modes>", RPL_MYINFO, nick, servername, VERSION)
}

func ReplyUModeIs(c *Client) string {
	return fmt.Sprintf("%s %s %s", RPL_UMODEIS, c.Nick(), c.UModeString())
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

func ErrUsersDontMatch(nick string) string {
	return fmt.Sprintf("%s %s :Cannot change mode for other users", ERR_USERSDONTMATCH, nick)
}

func MessagePong() string {
	return "PONG"
}

func MessageError() string {
	return "ERROR :Bye"
}
