package irc

import (
	"fmt"
	"strings"
	"time"
)

type BaseReply struct {
	code    ReplyCode
	id      string
	message string
	source  Identifier
}

func (reply *BaseReply) Code() ReplyCode {
	return reply.code
}

func (reply *BaseReply) SetSource(source Identifier) {
	reply.id = source.Id()
	reply.source = source
}

func (reply *BaseReply) Source() Identifier {
	return reply.source
}

type StringReply struct {
	BaseReply
}

func NewStringReply(source Identifier, code StringCode,
	format string, args ...interface{}) *StringReply {
	reply := &StringReply{}
	reply.code = code
	reply.message = fmt.Sprintf(format, args...)
	reply.SetSource(source)
	return reply
}

func (reply *StringReply) Format(client *Client) []string {
	message := fmt.Sprintf(":%s %s %s",
		reply.id, reply.code, reply.message)
	return []string{message}
}

func (reply *StringReply) String() string {
	return fmt.Sprintf("Reply(source=%s, code=%s, message=%s)",
		reply.id, reply.code, reply.message)
}

type NumericReply struct {
	BaseReply
}

func NewNumericReply(source Identifier, code NumericCode, format string,
	args ...interface{}) *NumericReply {
	reply := &NumericReply{}
	reply.code = code
	reply.message = fmt.Sprintf(format, args...)
	reply.SetSource(source)
	return reply
}

func (reply *NumericReply) Format(client *Client) []string {
	message := fmt.Sprintf(":%s %s %s %s",
		reply.id, reply.code, client.Nick(), reply.message)
	return []string{message}
}

func (reply *NumericReply) String() string {
	return fmt.Sprintf("Reply(source=%s, code=%d, message=%s)",
		reply.id, reply.code, reply.message)
}

//
// multiline replies
//

type MultilineReply interface {
	formatLine(*Client, []string) string
	names() []string
}

func joinedLen(names []string) int {
	var l = len(names) - 1 // " " between names
	for _, name := range names {
		l += len(name)
	}
	return l
}

func multilineFormat(reply MultilineReply, client *Client) []string {
	lines := make([]string, 0)
	baseLen := len(reply.formatLine(client, []string{}))
	tooLong := func(names []string) bool {
		return (baseLen + joinedLen(names)) > MAX_REPLY_LEN
	}
	from, to := 0, 1
	names := reply.names()
	for to < len(names) {
		if (from < (to - 1)) && tooLong(names[from:to]) {
			lines = append(lines, reply.formatLine(client, names[from:to-1]))
			from, to = to-1, to
		} else {
			to += 1
		}
	}
	if from < len(names) {
		lines = append(lines, reply.formatLine(client, names[from:]))
	}
	return lines
}

// names

type NamesReply struct {
	BaseReply
	channel *Channel
}

func NewNamesReply(channel *Channel) Reply {
	reply := &NamesReply{
		channel: channel,
	}
	reply.SetSource(channel.server)
	return reply
}

func (reply *NamesReply) names() []string {
	return reply.channel.Nicks()
}

func (reply *NamesReply) formatLine(client *Client, names []string) string {
	return RplNamReply(reply.channel, names).Format(client)[0]
}

func (reply *NamesReply) Format(client *Client) []string {
	lines := multilineFormat(reply, client)
	lines = append(lines, RplEndOfNames(reply.channel).Format(client)...)
	return lines
}

func (reply *NamesReply) String() string {
	return fmt.Sprintf("NamesReply(channel=%s, names=%s)",
		reply.channel, reply.channel.Nicks())
}

// whois channels

type WhoisChannelsReply struct {
	BaseReply
	client *Client
}

func NewWhoisChannelsReply(client *Client) *WhoisChannelsReply {
	reply := &WhoisChannelsReply{
		client: client,
	}
	reply.SetSource(client.server)
	return reply
}

func (reply *WhoisChannelsReply) names() []string {
	chstrs := make([]string, len(reply.client.channels))
	index := 0
	for channel := range reply.client.channels {
		switch {
		case channel.members[reply.client][ChannelOperator]:
			chstrs[index] = "@" + channel.name

		case channel.members[reply.client][Voice]:
			chstrs[index] = "+" + channel.name

		default:
			chstrs[index] = channel.name
		}
		index += 1
	}
	return chstrs
}

func (reply *WhoisChannelsReply) formatLine(client *Client, names []string) string {
	return RplWhoisChannels(reply.client, names).Format(client)[0]
}

func (reply *WhoisChannelsReply) Format(client *Client) []string {
	return multilineFormat(reply, client)
}

//
// messaging replies
//

func RplPrivMsg(source Identifier, target Identifier, message string) Reply {
	return NewStringReply(source, PRIVMSG, "%s :%s", target.Nick(), message)
}

func RplNotice(source Identifier, target Identifier, message string) Reply {
	return NewStringReply(source, NOTICE, "%s :%s", target.Nick(), message)
}

func RplNick(source Identifier, newNick string) Reply {
	return NewStringReply(source, NICK, newNick)
}

func RplJoin(client *Client, channel *Channel) Reply {
	return NewStringReply(client, JOIN, channel.name)
}

func RplPart(client *Client, channel *Channel, message string) Reply {
	return NewStringReply(client, PART, "%s :%s", channel, message)
}

func RplMode(client *Client, changes ModeChanges) Reply {
	return NewStringReply(client, MODE, "%s :%s", client.Nick(), changes)
}

func RplChannelMode(client *Client, channel *Channel,
	changes ChannelModeChanges) Reply {
	return NewStringReply(client, MODE, "%s %s", channel, changes)
}

func RplTopicMsg(source Identifier, channel *Channel) Reply {
	return NewStringReply(source, TOPIC, "%s :%s", channel, channel.topic)
}

func RplPing(server *Server, target Identifier) Reply {
	return NewStringReply(server, PING, target.Nick())
}

func RplPong(server *Server, client *Client) Reply {
	return NewStringReply(server, PONG, client.Nick())
}

func RplQuit(client *Client, message string) Reply {
	return NewStringReply(client, QUIT, ":%s", message)
}

func RplError(server *Server, message string) Reply {
	return NewStringReply(server, ERROR, message)
}

func RplInviteMsg(channel *Channel, inviter *Client) Reply {
	return NewStringReply(inviter, INVITE, channel.name)
}

func RplKick(channel *Channel, client *Client, target *Client, comment string) Reply {
	return NewStringReply(client, KICK, "%s %s :%s",
		channel, target.Nick(), comment)
}

// numeric replies

func RplWelcome(source Identifier, client *Client) Reply {
	return NewNumericReply(source, RPL_WELCOME,
		":Welcome to the Internet Relay Network %s", client.Id())
}

func RplYourHost(server *Server) Reply {
	return NewNumericReply(server, RPL_YOURHOST,
		":Your host is %s, running version %s", server.name, VERSION)
}

func RplCreated(server *Server) Reply {
	return NewNumericReply(server, RPL_CREATED,
		":This server was created %s", server.ctime.Format(time.RFC1123))
}

func RplMyInfo(server *Server) Reply {
	return NewNumericReply(server, RPL_MYINFO,
		"%s %s aiOorsw abeIikmntpqrsl", server.name, VERSION)
}

func RplUModeIs(server *Server, client *Client) Reply {
	return NewNumericReply(server, RPL_UMODEIS, client.ModeString())
}

func RplNoTopic(channel *Channel) Reply {
	return NewNumericReply(channel.server, RPL_NOTOPIC,
		"%s :No topic is set", channel.name)
}

func RplTopic(channel *Channel) Reply {
	return NewNumericReply(channel.server, RPL_TOPIC,
		"%s :%s", channel.name, channel.topic)
}

// <nick> <channel>
// NB: correction in errata
func RplInvitingMsg(channel *Channel, invitee *Client) Reply {
	return NewNumericReply(channel.server, RPL_INVITING,
		"%s %s", invitee.Nick(), channel.name)
}

func RplNamReply(channel *Channel, names []string) *NumericReply {
	return NewNumericReply(channel.server, RPL_NAMREPLY, "= %s :%s",
		channel.name, strings.Join(names, " "))
}

func RplEndOfNames(channel *Channel) Reply {
	return NewNumericReply(channel.server, RPL_ENDOFNAMES,
		"%s :End of NAMES list", channel.name)
}

// :You are now an IRC operator
func RplYoureOper(server *Server) Reply {
	return NewNumericReply(server, RPL_YOUREOPER, ":You are now an IRC operator")
}

func RplWhoisUser(client *Client) Reply {
	return NewNumericReply(client.server, RPL_WHOISUSER, "%s %s %s * :%s",
		client.Nick(), client.username, client.hostname, client.realname)
}

func RplWhoisOperator(client *Client) Reply {
	return NewNumericReply(client.server, RPL_WHOISOPERATOR,
		"%s :is an IRC operator", client.Nick())
}

func RplWhoisIdle(client *Client) Reply {
	return NewNumericReply(client.server, RPL_WHOISIDLE,
		"%s %d %d :seconds idle, signon time",
		client.Nick(), client.IdleSeconds(), client.SignonTime())
}

func RplWhoisChannels(client *Client, chstrs []string) Reply {
	return NewNumericReply(client.server, RPL_WHOISCHANNELS,
		"%s :%s", client.Nick(), strings.Join(chstrs, " "))
}

func RplEndOfWhois(server *Server) Reply {
	return NewNumericReply(server, RPL_ENDOFWHOIS, ":End of WHOIS list")
}

func RplChannelModeIs(channel *Channel) Reply {
	return NewNumericReply(channel.server, RPL_CHANNELMODEIS, "%s %s",
		channel, channel.ModeString())
}

// <channel> <user> <host> <server> <nick> ( "H" / "G" ) ["*"] [ ( "@" / "+" ) ]
// :<hopcount> <real name>
func RplWhoReply(channel *Channel, client *Client) Reply {
	channelName := "*"
	flags := ""

	if client.flags[Away] {
		flags = "G"
	} else {
		flags = "H"
	}
	if client.flags[Operator] {
		flags += "*"
	}

	if channel != nil {
		channelName = channel.name

		if channel.members[client][ChannelOperator] {
			flags += "@"
		} else if channel.members[client][Voice] {
			flags += "+"
		}
	}
	return NewNumericReply(client.server, RPL_WHOREPLY,
		"%s %s %s %s %s %s :%d %s",
		channelName, client.username, client.hostname, client.server.name,
		client.Nick(), flags, client.hops, client.realname)
}

// <name> :End of WHO list
func RplEndOfWho(server *Server, name string) Reply {
	return NewNumericReply(server, RPL_ENDOFWHO, "%s :End of WHO list", name)
}

func RplBanList(channel *Channel, ban UserMask) Reply {
	return NewNumericReply(channel.server, RPL_BANLIST, "%s %s", channel.name, ban)
}

func RplEndOfBanList(channel *Channel) Reply {
	return NewNumericReply(channel.server, RPL_ENDOFBANLIST,
		"%s :End of channel ban list", channel.name)
}

func RplNowAway(server *Server) Reply {
	return NewNumericReply(server, RPL_NOWAWAY,
		":You have been marked as being away")
}

func RplUnAway(server *Server) Reply {
	return NewNumericReply(server, RPL_UNAWAY,
		":You are no longer marked as being away")
}

func RplAway(server *Server, client *Client) Reply {
	return NewNumericReply(server, RPL_AWAY,
		"%s :%s", client.Nick(), client.awayMessage)
}

func RplIsOn(server *Server, nicks []string) Reply {
	return NewNumericReply(server, RPL_ISON,
		":%s", strings.Join(nicks, " "))
}

func RplMOTDStart(server *Server) Reply {
	return NewNumericReply(server, RPL_MOTDSTART,
		":- %s Message of the day - ", server.name)
}

func RplMOTD(server *Server, line string) Reply {
	return NewNumericReply(server, RPL_MOTD,
		":- %s", line)
}

func RplMOTDEnd(server *Server) Reply {
	return NewNumericReply(server, RPL_ENDOFMOTD,
		":End of MOTD command")
}

func RplList(channel *Channel) Reply {
	return NewNumericReply(channel.server, RPL_LIST, "%s %d :%s",
		channel, len(channel.members), channel.topic)
}

func RplListEnd(server *Server) Reply {
	return NewNumericReply(server, RPL_LISTEND, ":End of LIST")
}

//
// errors (also numeric)
//

func ErrAlreadyRegistered(source Identifier) Reply {
	return NewNumericReply(source, ERR_ALREADYREGISTRED,
		":You may not reregister")
}

func ErrNickNameInUse(source Identifier, nick string) Reply {
	return NewNumericReply(source, ERR_NICKNAMEINUSE,
		"%s :Nickname is already in use", nick)
}

func ErrUnknownCommand(source Identifier, code StringCode) Reply {
	return NewNumericReply(source, ERR_UNKNOWNCOMMAND,
		"%s :Unknown command", code)
}

func ErrUsersDontMatch(source Identifier) Reply {
	return NewNumericReply(source, ERR_USERSDONTMATCH,
		":Cannot change mode for other users")
}

func ErrNeedMoreParams(source Identifier, command string) Reply {
	return NewNumericReply(source, ERR_NEEDMOREPARAMS,
		"%s :Not enough parameters", command)
}

func ErrNoSuchChannel(server *Server, channel string) Reply {
	return NewNumericReply(server, ERR_NOSUCHCHANNEL,
		"%s :No such channel", channel)
}

func ErrUserOnChannel(channel *Channel, member *Client) Reply {
	return NewNumericReply(channel.server, ERR_USERONCHANNEL,
		"%s %s :is already on channel", member.Nick(), channel.name)
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
		"%s :Channel doesn't support modes", channel)
}

func ErrNoPrivileges(server *Server) Reply {
	return NewNumericReply(server, ERR_NOPRIVILEGES, ":Permission Denied")
}

func ErrRestricted(server *Server) Reply {
	return NewNumericReply(server, ERR_RESTRICTED, ":Your connection is restricted!")
}

func ErrNoSuchServer(server *Server, target string) Reply {
	return NewNumericReply(server, ERR_NOSUCHSERVER, "%s :No such server", target)
}

func ErrUserNotInChannel(channel *Channel, client *Client) Reply {
	return NewNumericReply(channel.server, ERR_USERNOTINCHANNEL,
		"%s %s :They aren't on that channel", client.Nick(), channel)
}

func ErrCannotSendToChan(channel *Channel) Reply {
	return NewNumericReply(channel.server, ERR_CANNOTSENDTOCHAN,
		"%s :Cannot send to channel", channel)
}

// <channel> :You're not channel operator
func ErrChanOPrivIsNeeded(channel *Channel) Reply {
	return NewNumericReply(channel.server, ERR_CHANOPRIVSNEEDED,
		"%s :You're not channel operator", channel)
}

func ErrNoMOTD(server *Server) Reply {
	return NewNumericReply(server, ERR_NOMOTD, ":MOTD File is missing")
}

func ErrNoNicknameGiven(server *Server) Reply {
	return NewNumericReply(server, ERR_NONICKNAMEGIVEN, ":No nickname given")
}

func ErrErroneusNickname(server *Server, nick string) Reply {
	return NewNumericReply(server, ERR_ERRONEUSNICKNAME,
		"%s :Erroneous nickname", nick)
}
