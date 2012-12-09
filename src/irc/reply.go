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

func (reply *BasicReply) String(client *Client) string {
	prefix := fmt.Sprintf(":%s %s %s ", reply.source.Id(), reply.code, client.Nick())
	return prefix + reply.message
}

type ChannelReply struct {
	*BasicReply
	channel *Channel
}

func (reply *ChannelReply) String(client *Client) string {
	prefix := fmt.Sprintf(":%s %s %s ", reply.source.Id(), reply.code, reply.channel.name)
	return prefix + reply.message
}

func NewReply(source Identifier, code string, message string) *BasicReply {
	return &BasicReply{source, code, message}
}

// messaging

func RplPrivMsg(source *Client, message string) Reply {
	return NewReply(source, RPL_PRIVMSG, ":"+message)
}

func RplNick(client *Client, newNick string) Reply {
	return NewReply(client, RPL_NICK, ":"+newNick)
}

func RplPrivMsgChannel(channel *Channel, source *Client, message string) Reply {
	return &ChannelReply{NewReply(source, RPL_PRIVMSG, ":"+message), channel}
}

func RplJoin(channel *Channel, client *Client) Reply {
	return &ChannelReply{NewReply(client, RPL_JOIN, channel.name), channel}
}

func RplPart(channel *Channel, client *Client, message string) Reply {
	return &ChannelReply{NewReply(client, RPL_PART, ":"+message), channel}
}

// Server Info

func RplWelcome(source Identifier, client *Client) Reply {
	return NewReply(source, RPL_WELCOME, "Welcome to the Internet Relay Network "+client.Id())
}

func RplYourHost(server *Server, target *Client) Reply {
	return NewReply(server, RPL_YOURHOST, fmt.Sprintf("Your host is %s, running version %s", server.hostname, VERSION))
}

func RplCreated(server *Server) Reply {
	return NewReply(server, RPL_CREATED, "This server was created "+server.ctime.Format(time.RFC1123))
}

func RplMyInfo(server *Server) Reply {
	return NewReply(server, RPL_MYINFO, fmt.Sprintf("%s %s i ik", server.name, VERSION))
}

func RplUModeIs(server *Server, client *Client) Reply {
	return NewReply(server, RPL_UMODEIS, client.UModeString())
}

// channel operations

func RplNoTopic(channel *Channel) Reply {
	return &ChannelReply{NewReply(channel.server, RPL_NOTOPIC, channel.name+" :No topic is set"), channel}
}

func RplTopic(channel *Channel) Reply {
	return &ChannelReply{NewReply(channel.server, RPL_TOPIC, fmt.Sprintf("%s :%s", channel.name, channel.topic)), channel}
}

func RplNamReply(channel *Channel) Reply {
	// TODO multiple names and splitting based on message size
	return NewReply(channel.server, RPL_NAMREPLY, fmt.Sprintf("= %s :%s", channel.name, strings.Join(channel.Nicks(), " ")))
}

func RplEndOfNames(source Identifier) Reply {
	return NewReply(source, RPL_ENDOFNAMES, ":End of NAMES list")
}

func RplPong(server *Server) Reply {
	return NewReply(server, RPL_PONG, "")
}

// errors

func ErrAlreadyRegistered(source Identifier) Reply {
	return NewReply(source, ERR_ALREADYREGISTRED, ":You may not reregister")
}

func ErrNickNameInUse(source Identifier, nick string) Reply {
	return NewReply(source, ERR_NICKNAMEINUSE, nick+" :Nickname is already in use")
}

func ErrUnknownCommand(source Identifier, command string) Reply {
	return NewReply(source, ERR_UNKNOWNCOMMAND, command+" :Unknown command")
}

func ErrUsersDontMatch(source Identifier) Reply {
	return NewReply(source, ERR_USERSDONTMATCH, ":Cannot change mode for other users")
}

func ErrNeedMoreParams(source Identifier, command string) Reply {
	return NewReply(source, ERR_NEEDMOREPARAMS, command+"%s :Not enough parameters")
}

func ErrNoSuchChannel(source Identifier, channel string) Reply {
	return NewReply(source, ERR_NOSUCHCHANNEL, channel+" :No such channel")
}

func ErrNotOnChannel(channel *Channel) Reply {
	return NewReply(channel.server, ERR_NOTONCHANNEL, channel.name+" :You're not on that channel")
}

func ErrInviteOnlyChannel(channel *Channel) Reply {
	return NewReply(channel.server, ERR_INVITEONLYCHANNEL, channel.name+" :Cannot join channel (+i)")
}

func ErrBadChannelKey(channel *Channel) Reply {
	return NewReply(channel.server, ERR_BADCHANNELKEY, channel.name+" :Cannot join channel (+k)")
}

func ErrNoSuchNick(source Identifier, nick string) Reply {
	return NewReply(source, ERR_NOSUCHNICK, nick+" :No such nick/channel")
}
