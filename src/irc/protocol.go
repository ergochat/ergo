package irc

import (
	"fmt"
)

const (
	VERSION = "goircd-1"
)

const (
	RPL_WELCOME  = "001"
	RPL_YOURHOST = "002"
	RPL_CREATED  = "003"
	RPL_MYINFO   = "004"
	RPL_NONE     = "300"
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

const (
	ERR_NOSUCHNICK       = "401"
	ERR_NOSUCHSERVER     = "402"
	ERR_NOSUCHCHANNEL    = "403"
	ERR_UNKNOWNCOMMAND   = "421"
	ERR_NICKNAMEINUSE    = "433"
	ERR_NEEDMOREPARAMS   = "461"
	ERR_ALREADYREGISTRED = "462"
	ERR_USERSDONTMATCH   = "502"
)

func ErrAlreadyRegistered(nick string) string {
	return fmt.Sprintf("%s %s :You may not reregister", ERR_ALREADYREGISTRED, nick)
}

func ErrNickNameInUse(nick string) string {
	return fmt.Sprintf("%s %s :Nickname is already in use", ERR_NICKNAMEINUSE, nick)
}

func ErrUnknownCommand(nick string, command string) string {
	return fmt.Sprintf("%s %s %s :Unknown command", ERR_UNKNOWNCOMMAND, nick, command)
}


const (
	RE_PASS     = "(?P<password>\\S+)"
	RE_NICK     = "(?P<nickname>\\S+)"
	RE_USER     = "(?P<user>\\S+) (?P<mode>\\d) (?:\\S+) :(?P<realname>.+)"
	RE_OPER     = "(?P<name>\\S+) (?P<password>\\S+)"
	RE_MODE     = "(?P<nickname>\\S+)(?: (?P<mode>[-+][iwroOs]+))*"
	RE_SERVICE  = "(?P<nickname>\\S+) (?P<reserved1>\\S+) (?P<distribution>\\S+) (?P<type>\\S+) (?P<reserved2>\\S+) :(?P<info>.+)"
	RE_QUIT     = ":(?P<message>.*)"
	RE_SQUIT    = "(?P<server>\\S+) :(?P<comment>.+)"
	RE_JOIN     = "0|(?:(?P<channels>\\S+(?:,\\S+)*)(?: (?P<keys>\\S+(?:,\\S+)*))?)"
	RE_PART     = "(?P<channels>\\S+(?:,\\S+)*)(?: :(?P<message>.+))?"
	RE_MODE_CH  = "(?P<channel>\\S+)(?: (?P<mode>[-+][iwroOs]+))*" // XXX incomplete
	RE_TOPIC    = "(?P<channel>\\S+)(?: :(?P<topic>.+))?"
	RE_NAMES    = "(?:(?P<channels>\\S+(?:,\\S+)*)(?: (?P<target>\\S+))?)?"
	RE_LIST     = "(?:(?P<channels>\\S+(?:,\\S+)*)(?: (?P<target>\\S+))?)?"
	RE_INVITE   = "(?P<nickname>\\S+) (?P<channel>\\S+)"
	RE_KICK     = "(?P<channels>\\S+(?:,\\S+)*) (?P<users>\\S+(?:,\\S+))(?: :(?P<comment>.+))?"
	RE_PRIVMSG  = "(?P<target>\\S+) :(?P<text>.+)"
	RE_NOTICE   = "(?P<target>\\S+) :(?P<text>.+)"
	RE_MOTD     = "(?P<target>\\S+)?"
	RE_LUSERS   = "(?:(?P<mask>\\S+)(?: (?P<target>\\S+))?)?"
	RE_VERSION  = "(?P<target>\\S+)?"
	RE_STATS    = "(?:(?P<query>\\S+)(?: (?P<target>\\S+))?)?"
	RE_LINKS    = "(?:(?P<remote>\\S+) )?(?P<mask>\\S+)"
	RE_TIME     = "(?P<target>\\S+)?"
	RE_CONNECT  = "(?P<target>\\S+) (?P<port>\\d+)(?: (?P<remote>\\S+))?"
	RE_TRACE    = "(?P<target>\\S+)?"
	RE_ADMIN    = "(?P<target>\\S+)?"
	RE_INFO     = "(?P<target>\\S+)?"
	RE_SERVLIST = "" // XXX
	RE_SQUERY   = "" // XXX
	RE_WHO      = "" // XXX
	RE_WHOIS    = "" // XXX
	RE_WHOWAS   = "" // XXX
	RE_KILL     = "(?P<nickname>\\S+) :(?P<comment>.+)"
	RE_PING     = "(?P<server1>\\S+)(?: (?P<server2>\\S+))?"
	RE_PONG     = "(?P<server1>\\S+)(?: (?P<server2>\\S+))?"
	RE_ERROR    = ":(?P<error>.+)"
	RE_AWAY     = ":(?P<text>.+)"
	RE_REHASH   = ""
	RE_DIE      = ""
	RE_RESTART  = ""
	RE_SUMMON   = "(?P<user>\\S+)(?: (?P<target>\\S+)(?: (?P<channel>\\S+))?)?"
	RE_USERS    = "(?P<target>\\S+)?"
	RE_WALLOPS  = ":(?P<text>.+)"
	RE_USERHOST = "(?P<nicknames>\\S+(?: \\S+)*)"
	RE_ISON     = "(?P<nicknames>\\S+(?: \\S+)*)"
)

func MessagePong() string {
	return "PONG"
}

func MessageError() string {
	return "ERROR :Bye"
}
