package irc

import (
	"fmt"
	"strings"
	"time"
)

type Identifier interface {
	Id() string
}

type Reply interface {
	String(client *Client) string
}

type BasicReply struct {
	source  Identifier
	code    string
	message string
}

func NewBasicReply(source Identifier, code string, message string) *BasicReply {
	fullMessage := fmt.Sprintf(":%s %s %s\r\n", source.Id(), code, message)
	return &BasicReply{source, code, fullMessage}
}

func (reply *BasicReply) String(client *Client) string {
	return reply.message
}

type NumericReply struct {
	*BasicReply
}

func NewNumericReply(source Identifier, code string, message string) *NumericReply {
	return &NumericReply{&BasicReply{source, code, message}}
}

func (reply *NumericReply) String(client *Client) string {
	return fmt.Sprintf(":%s %s %s %s\r\n", reply.source.Id(), reply.code, client.Nick(),
		reply.message)
}

// messaging replies

func RplPrivMsg(source *Client, target *Client, message string) Reply {
	return NewBasicReply(source, RPL_PRIVMSG, fmt.Sprintf("%s :%s", target, message))
}

func RplNick(client *Client, newNick string) Reply {
	return NewBasicReply(client, RPL_NICK, newNick)
}

func RplPrivMsgChannel(channel *Channel, source *Client, message string) Reply {
	return NewBasicReply(source, RPL_PRIVMSG, fmt.Sprintf("%s :%s", channel.name, message))
}

func RplJoin(channel *Channel, client *Client) Reply {
	return NewBasicReply(client, RPL_JOIN, channel.name)
}

func RplPart(channel *Channel, client *Client, message string) Reply {
	return NewBasicReply(client, RPL_PART, fmt.Sprintf("%s :%s", channel.name, message))
}

func RplPong(server *Server) Reply {
	return NewBasicReply(server, RPL_PONG, server.Id())
}

func RplQuit(client *Client, message string) Reply {
	return NewBasicReply(client, RPL_QUIT, ":"+message)
}

func RplInviteMsg(channel *Channel, inviter *Client) Reply {
	return NewBasicReply(inviter, RPL_INVITE, channel.name)
}

// numeric replies

func RplWelcome(source Identifier, client *Client) Reply {
	return NewNumericReply(source, RPL_WELCOME,
		"Welcome to the Internet Relay Network "+client.Id())
}

func RplYourHost(server *Server, target *Client) Reply {
	return NewNumericReply(server, RPL_YOURHOST,
		fmt.Sprintf("Your host is %s, running version %s", server.hostname, VERSION))
}

func RplCreated(server *Server) Reply {
	return NewNumericReply(server, RPL_CREATED,
		"This server was created "+server.ctime.Format(time.RFC1123))
}

func RplMyInfo(server *Server) Reply {
	return NewNumericReply(server, RPL_MYINFO,
		fmt.Sprintf("%s %s w kn", server.name, VERSION))
}

func RplUModeIs(server *Server, client *Client) Reply {
	return NewNumericReply(server, RPL_UMODEIS, client.UModeString())
}

func RplNoTopic(channel *Channel) Reply {
	return NewNumericReply(channel.server, RPL_NOTOPIC, channel.name+" :No topic is set")
}

func RplTopic(channel *Channel) Reply {
	return NewNumericReply(channel.server, RPL_TOPIC, fmt.Sprintf("%s :%s", channel.name, channel.topic))
}

func RplInvitingMsg(channel *Channel, invitee *Client) Reply {
	return NewNumericReply(channel.server, RPL_INVITING,
		fmt.Sprintf("%s %s", channel.name, invitee.Nick()))
}

func RplNamReply(channel *Channel) Reply {
	// TODO multiple names and splitting based on message size
	return NewNumericReply(channel.server, RPL_NAMREPLY,
		fmt.Sprintf("= %s :%s", channel.name, strings.Join(channel.Nicks(), " ")))
}

func RplEndOfNames(source Identifier) Reply {
	return NewNumericReply(source, RPL_ENDOFNAMES, ":End of NAMES list")
}

func RplYoureOper(server *Server) Reply {
	return NewNumericReply(server, RPL_YOUREOPER, ":You are now an IRC operator")
}

// errors (also numeric)

func ErrAlreadyRegistered(source Identifier) Reply {
	return NewNumericReply(source, ERR_ALREADYREGISTRED, ":You may not reregister")
}

func ErrNickNameInUse(source Identifier, nick string) Reply {
	return NewNumericReply(source, ERR_NICKNAMEINUSE,
		nick+" :Nickname is already in use")
}

func ErrUnknownCommand(source Identifier, command string) Reply {
	return NewNumericReply(source, ERR_UNKNOWNCOMMAND,
		command+" :Unknown command")
}

func ErrUsersDontMatch(source Identifier) Reply {
	return NewNumericReply(source, ERR_USERSDONTMATCH,
		":Cannot change mode for other users")
}

func ErrNeedMoreParams(source Identifier, command string) Reply {
	return NewNumericReply(source, ERR_NEEDMOREPARAMS,
		command+"%s :Not enough parameters")
}

func ErrNoSuchChannel(source Identifier, channel string) Reply {
	return NewNumericReply(source, ERR_NOSUCHCHANNEL,
		channel+" :No such channel")
}

func ErrUserOnChannel(channel *Channel, member *Client) Reply {
	return NewNumericReply(channel.server, ERR_USERONCHANNEL,
		fmt.Sprintf("%s %s :is already on channel", member.nick, channel.name))
}

func ErrNotOnChannel(channel *Channel) Reply {
	return NewNumericReply(channel.server, ERR_NOTONCHANNEL,
		channel.name+" :You're not on that channel")
}

func ErrInviteOnlyChannel(channel *Channel) Reply {
	return NewNumericReply(channel.server, ERR_INVITEONLYCHAN,
		channel.name+" :Cannot join channel (+i)")
}

func ErrBadChannelKey(channel *Channel) Reply {
	return NewNumericReply(channel.server, ERR_BADCHANNELKEY,
		channel.name+" :Cannot join channel (+k)")
}

func ErrNoSuchNick(source Identifier, nick string) Reply {
	return NewNumericReply(source, ERR_NOSUCHNICK,
		nick+" :No such nick/channel")
}

func ErrPasswdMismatch(server *Server) Reply {
	return NewNumericReply(server, ERR_PASSWDMISMATCH, ":Password incorrect")
}

func ErrNoChanModes(channel *Channel) Reply {
	return NewNumericReply(channel.server, ERR_NOCHANMODES,
		channel.name+" :Channel doesn't support modes")
}
