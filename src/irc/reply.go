package irc

import (
	"fmt"
	"strings"
	"time"
)

type Identifier interface {
	Id() string
	PublicId() string
	Nick() string
}

type Reply interface {
	String(client *Client) string
	Source() Identifier
}

type BasicReply struct {
	source  Identifier
	code    string
	message string
}

func NewBasicReply(source Identifier, code string,
	format string, args ...interface{}) *BasicReply {
	message := fmt.Sprintf(format, args...)
	fullMessage := fmt.Sprintf(":%s %s %s\r\n", source.Id(), code, message)
	return &BasicReply{source, code, fullMessage}
}

func (reply *BasicReply) String(client *Client) string {
	return reply.message
}

func (reply *BasicReply) Source() Identifier {
	return reply.source
}

type NumericReply struct {
	*BasicReply
}

func NewNumericReply(source Identifier, code string,
	format string, args ...interface{}) *NumericReply {
	return &NumericReply{&BasicReply{source, code, fmt.Sprintf(format, args...)}}
}

func (reply *NumericReply) String(client *Client) string {
	return fmt.Sprintf(":%s %s %s %s\r\n", reply.source.Id(), reply.code, client.Nick(),
		reply.message)
}

// messaging replies

func RplPrivMsg(source Identifier, target Identifier, message string) Reply {
	return NewBasicReply(source, RPL_PRIVMSG, "%s :%s", target.Nick(), message)
}

func RplNick(client *Client, newNick string) Reply {
	return NewBasicReply(client, RPL_NICK, newNick)
}

func RplPrivMsgChannel(channel *Channel, source Identifier, message string) Reply {
	return NewBasicReply(source, RPL_PRIVMSG, "%s :%s", channel.name, message)
}

func RplJoin(channel *Channel, user *User) Reply {
	return NewBasicReply(user, RPL_JOIN, channel.name)
}

func RplPart(channel *Channel, user *User, message string) Reply {
	return NewBasicReply(user, RPL_PART, "%s :%s", channel.name, message)
}

func RplPong(server *Server) Reply {
	return NewBasicReply(server, RPL_PONG, server.Id())
}

func RplQuit(client *Client, message string) Reply {
	return NewBasicReply(client, RPL_QUIT, ":%", message)
}

func RplInviteMsg(channel *Channel, inviter *Client) Reply {
	return NewBasicReply(inviter, RPL_INVITE, channel.name)
}

// numeric replies

func RplWelcome(source Identifier, client *Client) Reply {
	return NewNumericReply(source, RPL_WELCOME,
		"Welcome to the Internet Relay Network %s", client.Id())
}

func RplYourHost(server *Server, target *Client) Reply {
	return NewNumericReply(server, RPL_YOURHOST,
		"Your host is %s, running version %s", server.hostname, VERSION)
}

func RplCreated(server *Server) Reply {
	return NewNumericReply(server, RPL_CREATED,
		"This server was created %s", server.ctime.Format(time.RFC1123))
}

func RplMyInfo(server *Server) Reply {
	return NewNumericReply(server, RPL_MYINFO,
		"%s %s a kn", server.name, VERSION)
}

func RplUModeIs(server *Server, client *Client) Reply {
	return NewNumericReply(server, RPL_UMODEIS,
		client.UModeString())
}

func RplNoTopic(channel *Channel) Reply {
	return NewNumericReply(channel.server, RPL_NOTOPIC,
		"%s :No topic is set", channel.name)
}

func RplTopic(channel *Channel) Reply {
	return NewNumericReply(channel.server, RPL_TOPIC,
		"%s :%s", channel.name, channel.topic)
}

func RplInvitingMsg(channel *Channel, invitee *Client) Reply {
	return NewNumericReply(channel.server, RPL_INVITING,
		"%s %s", channel.name, invitee.Nick())
}

func RplNamReply(channel *Channel) Reply {
	// TODO multiple names and splitting based on message size
	return NewNumericReply(channel.server, RPL_NAMREPLY,
		"= %s :%s", channel.name, strings.Join(channel.Nicks(), " "))
}

func RplEndOfNames(source Identifier) Reply {
	return NewNumericReply(source, RPL_ENDOFNAMES,
		":End of NAMES list")
}

func RplYoureOper(server *Server) Reply {
	return NewNumericReply(server, RPL_YOUREOPER,
		":You are now an IRC operator")
}

// errors (also numeric)

func ErrAlreadyRegistered(source Identifier) Reply {
	return NewNumericReply(source, ERR_ALREADYREGISTRED,
		":You may not reregister")
}

func ErrNickNameInUse(source Identifier, nick string) Reply {
	return NewNumericReply(source, ERR_NICKNAMEINUSE,
		"%s :Nickname is already in use", nick)
}

func ErrUnknownCommand(source Identifier, command string) Reply {
	return NewNumericReply(source, ERR_UNKNOWNCOMMAND,
		"%s :Unknown command", command)
}

func ErrUsersDontMatch(source Identifier) Reply {
	return NewNumericReply(source, ERR_USERSDONTMATCH,
		":Cannot change mode for other users")
}

func ErrNeedMoreParams(source Identifier, command string) Reply {
	return NewNumericReply(source, ERR_NEEDMOREPARAMS,
		"%s :Not enough parameters", command)
}

func ErrNoSuchChannel(source Identifier, channel string) Reply {
	return NewNumericReply(source, ERR_NOSUCHCHANNEL,
		"%s :No such channel", channel)
}

func ErrUserOnChannel(channel *Channel, member *Client) Reply {
	return NewNumericReply(channel.server, ERR_USERONCHANNEL,
		"%s %s :is already on channel", member.nick, channel.name)
}

func ErrNotOnChannel(channel *Channel) Reply {
	return NewNumericReply(channel.server, ERR_NOTONCHANNEL,
		"%s :You're not on that channel", channel.name)
}

func ErrInviteOnlyChannel(channel *Channel) Reply {
	return NewNumericReply(channel.server, ERR_INVITEONLYCHAN,
		"%s :Cannot join channel (+i)", channel.name)
}

func ErrBadChannelKey(channel *Channel) Reply {
	return NewNumericReply(channel.server, ERR_BADCHANNELKEY,
		"%s :Cannot join channel (+k)", channel.name)
}

func ErrNoSuchNick(source Identifier, nick string) Reply {
	return NewNumericReply(source, ERR_NOSUCHNICK,
		"%s :No such nick/channel", nick)
}

func ErrPasswdMismatch(server *Server) Reply {
	return NewNumericReply(server, ERR_PASSWDMISMATCH, ":Password incorrect")
}

func ErrNoChanModes(channel *Channel) Reply {
	return NewNumericReply(channel.server, ERR_NOCHANMODES,
		"%s :Channel doesn't support modes", channel.name)
}

func ErrNoPrivileges(server *Server) Reply {
	return NewNumericReply(server, ERR_NOPRIVILEGES, ":Permission Denied")
}

func ErrRestricted(server *Server) Reply {
	return NewNumericReply(server, ERR_RESTRICTED, ":Your connection is restricted!")
}
