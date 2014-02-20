package irc

import (
	"fmt"
	"strings"
	"time"
)

func NewStringReply(source Identifier, code StringCode,
	format string, args ...interface{}) string {
	header := fmt.Sprintf(":%s %s ", source, code)
	message := fmt.Sprintf(format, args...)
	return header + message + CRLF
}

func NewNumericReply(target *Client, code NumericCode,
	format string, args ...interface{}) string {
	header := fmt.Sprintf(":%s %s %s ", target.server.Id(), code, target.Nick())
	message := fmt.Sprintf(format, args...)
	return header + message + CRLF
}

func (target *Client) NumericReply(code NumericCode,
	format string, args ...interface{}) {
	target.replies <- NewNumericReply(target, code, format, args...)
}

//
// multiline replies
//

func joinedLen(names []string) int {
	var l = len(names) - 1 // " " between names
	for _, name := range names {
		l += len(name)
	}
	return l
}

func (target *Client) MultilineReply(names []string, code NumericCode, format string,
	args ...interface{}) {
	baseLen := len(NewNumericReply(target, code, format))
	tooLong := func(names []string) bool {
		return (baseLen + joinedLen(names)) > MAX_REPLY_LEN
	}
	argsAndNames := func(names []string) []interface{} {
		return append(args, strings.Join(names, " "))
	}
	from, to := 0, 1
	for to < len(names) {
		if (from < (to - 1)) && tooLong(names[from:to]) {
			target.NumericReply(code, format, argsAndNames(names[from:to-1])...)
			from, to = to-1, to
		} else {
			to += 1
		}
	}
	if from < len(names) {
		target.NumericReply(code, format, argsAndNames(names[from:])...)
	}
}

//
// messaging replies
//

func RplPrivMsg(source Identifier, target Identifier, message string) string {
	return NewStringReply(source, PRIVMSG, "%s :%s", target.Nick(), message)
}

func RplNotice(source Identifier, target Identifier, message string) string {
	return NewStringReply(source, NOTICE, "%s :%s", target.Nick(), message)
}

func RplNick(source Identifier, newNick string) string {
	return NewStringReply(source, NICK, newNick)
}

func RplJoin(client *Client, channel *Channel) string {
	return NewStringReply(client, JOIN, channel.name)
}

func RplPart(client *Client, channel *Channel, message string) string {
	return NewStringReply(client, PART, "%s :%s", channel, message)
}

func RplMode(client *Client, target *Client, changes ModeChanges) string {
	return NewStringReply(client, MODE, "%s :%s", target.Nick(), changes)
}

func RplChannelMode(client *Client, channel *Channel,
	changes ChannelModeChanges) string {
	return NewStringReply(client, MODE, "%s %s", channel, changes)
}

func RplTopicMsg(source Identifier, channel *Channel) string {
	return NewStringReply(source, TOPIC, "%s :%s", channel, channel.topic)
}

func RplPing(server *Server, target Identifier) string {
	return NewStringReply(server, PING, target.Nick())
}

func RplPong(server *Server, client *Client) string {
	return NewStringReply(server, PONG, client.Nick())
}

func RplQuit(client *Client, message string) string {
	return NewStringReply(client, QUIT, ":%s", message)
}

func RplError(server *Server, message string) string {
	return NewStringReply(server, ERROR, ":%s", message)
}

func RplInviteMsg(channel *Channel, inviter *Client) string {
	return NewStringReply(inviter, INVITE, channel.name)
}

func RplKick(channel *Channel, client *Client, target *Client, comment string) string {
	return NewStringReply(client, KICK, "%s %s :%s",
		channel, target.Nick(), comment)
}

// numeric replies

func (target *Client) RplWelcome() {
	target.NumericReply(RPL_WELCOME,
		":Welcome to the Internet Relay Network %s", target.Id())
}

func (target *Client) RplYourHost() {
	target.NumericReply(RPL_YOURHOST,
		":Your host is %s, running version %s", target.server.name, VERSION)
}

func (target *Client) RplCreated() {
	target.NumericReply(RPL_CREATED,
		":This server was created %s", target.server.ctime.Format(time.RFC1123))
}

func (target *Client) RplMyInfo() {
	target.NumericReply(RPL_MYINFO,
		"%s %s aiOorsw abeIikmntpqrsl", target.server.name, VERSION)
}

func (target *Client) RplUModeIs(client *Client) {
	target.NumericReply(RPL_UMODEIS, client.ModeString())
}

func (target *Client) RplNoTopic(channel *Channel) {
	target.NumericReply(RPL_NOTOPIC,
		"%s :No topic is set", channel.name)
}

func (target *Client) RplTopic(channel *Channel) {
	target.NumericReply(RPL_TOPIC,
		"%s :%s", channel.name, channel.topic)
}

// <nick> <channel>
// NB: correction in errata
func (target *Client) RplInvitingMsg(channel *Channel, invitee *Client) {
	target.NumericReply(RPL_INVITING,
		"%s %s", invitee.Nick(), channel.name)
}

func (target *Client) RplEndOfNames(channel *Channel) {
	target.NumericReply(RPL_ENDOFNAMES,
		"%s :End of NAMES list", channel.name)
}

// :You are now an IRC operator
func (target *Client) RplYoureOper() {
	target.NumericReply(RPL_YOUREOPER,
		":You are now an IRC operator")
}

func (target *Client) RplWhoisUser(client *Client) {
	target.NumericReply(RPL_WHOISUSER,
		"%s %s %s * :%s", client.Nick(), client.username, client.hostname,
		client.realname)
}

func (target *Client) RplWhoisOperator(client *Client) {
	target.NumericReply(RPL_WHOISOPERATOR,
		"%s :is an IRC operator", client.Nick())
}

func (target *Client) RplWhoisIdle(client *Client) {
	target.NumericReply(RPL_WHOISIDLE,
		"%s %d %d :seconds idle, signon time",
		client.Nick(), client.IdleSeconds(), client.SignonTime())
}

func (target *Client) RplEndOfWhois() {
	target.NumericReply(RPL_ENDOFWHOIS,
		":End of WHOIS list")
}

func (target *Client) RplChannelModeIs(channel *Channel) {
	target.NumericReply(RPL_CHANNELMODEIS,
		"%s %s", channel, channel.ModeString())
}

// <channel> <user> <host> <server> <nick> ( "H" / "G" ) ["*"] [ ( "@" / "+" ) ]
// :<hopcount> <real name>
func (target *Client) RplWhoReply(channel *Channel, client *Client) {
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
	target.NumericReply(RPL_WHOREPLY,
		"%s %s %s %s %s %s :%d %s", channelName, client.username, client.hostname,
		client.server.name, client.Nick(), flags, client.hops, client.realname)
}

// <name> :End of WHO list
func (target *Client) RplEndOfWho(name string) {
	target.NumericReply(RPL_ENDOFWHO,
		"%s :End of WHO list", name)
}

func (target *Client) RplBanList(channel *Channel, ban UserMask) {
	target.NumericReply(RPL_BANLIST,
		"%s %s", channel.name, ban)
}

func (target *Client) RplEndOfBanList(channel *Channel) {
	target.NumericReply(RPL_ENDOFBANLIST,
		"%s :End of channel ban list", channel.name)
}

func (target *Client) RplNowAway() {
	target.NumericReply(RPL_NOWAWAY,
		":You have been marked as being away")
}

func (target *Client) RplUnAway() {
	target.NumericReply(RPL_UNAWAY,
		":You are no longer marked as being away")
}

func (target *Client) RplAway(client *Client) {
	target.NumericReply(RPL_AWAY,
		"%s :%s", client.Nick(), client.awayMessage)
}

func (target *Client) RplIsOn(nicks []string) {
	target.NumericReply(RPL_ISON,
		":%s", strings.Join(nicks, " "))
}

func (target *Client) RplMOTDStart() {
	target.NumericReply(RPL_MOTDSTART,
		":- %s Message of the day - ", target.server.name)
}

func (target *Client) RplMOTD(line string) {
	target.NumericReply(RPL_MOTD,
		":- %s", line)
}

func (target *Client) RplMOTDEnd() {
	target.NumericReply(RPL_ENDOFMOTD,
		":End of MOTD command")
}

func (target *Client) RplList(channel *Channel) {
	target.NumericReply(RPL_LIST,
		"%s %d :%s", channel, len(channel.members), channel.topic)
}

func (target *Client) RplListEnd(server *Server) {
	target.NumericReply(RPL_LISTEND,
		":End of LIST")
}

//
// errors (also numeric)
//

func (target *Client) ErrAlreadyRegistered() {
	target.NumericReply(ERR_ALREADYREGISTRED,
		":You may not reregister")
}

func (target *Client) ErrNickNameInUse(nick string) {
	target.NumericReply(ERR_NICKNAMEINUSE,
		"%s :Nickname is already in use", nick)
}

func (target *Client) ErrUnknownCommand(code StringCode) {
	target.NumericReply(ERR_UNKNOWNCOMMAND,
		"%s :Unknown command", code)
}

func (target *Client) ErrUsersDontMatch() {
	target.NumericReply(ERR_USERSDONTMATCH,
		":Cannot change mode for other users")
}

func (target *Client) ErrNeedMoreParams(command string) {
	target.NumericReply(ERR_NEEDMOREPARAMS,
		"%s :Not enough parameters", command)
}

func (target *Client) ErrNoSuchChannel(channel string) {
	target.NumericReply(ERR_NOSUCHCHANNEL,
		"%s :No such channel", channel)
}

func (target *Client) ErrUserOnChannel(channel *Channel, member *Client) {
	target.NumericReply(ERR_USERONCHANNEL,
		"%s %s :is already on channel", member.Nick(), channel.name)
}

func (target *Client) ErrNotOnChannel(channel *Channel) {
	target.NumericReply(ERR_NOTONCHANNEL,
		"%s :You're not on that channel", channel.name)
}

func (target *Client) ErrInviteOnlyChannel(channel *Channel) {
	target.NumericReply(ERR_INVITEONLYCHAN,
		"%s :Cannot join channel (+i)", channel.name)
}

func (target *Client) ErrBadChannelKey(channel *Channel) {
	target.NumericReply(ERR_BADCHANNELKEY,
		"%s :Cannot join channel (+k)", channel.name)
}

func (target *Client) ErrNoSuchNick(nick string) {
	target.NumericReply(ERR_NOSUCHNICK,
		"%s :No such nick/channel", nick)
}

func (target *Client) ErrPasswdMismatch() {
	target.NumericReply(ERR_PASSWDMISMATCH, ":Password incorrect")
}

func (target *Client) ErrNoChanModes(channel *Channel) {
	target.NumericReply(ERR_NOCHANMODES,
		"%s :Channel doesn't support modes", channel)
}

func (target *Client) ErrNoPrivileges() {
	target.NumericReply(ERR_NOPRIVILEGES, ":Permission Denied")
}

func (target *Client) ErrRestricted() {
	target.NumericReply(ERR_RESTRICTED, ":Your connection is restricted!")
}

func (target *Client) ErrNoSuchServer(server string) {
	target.NumericReply(ERR_NOSUCHSERVER, "%s :No such server", server)
}

func (target *Client) ErrUserNotInChannel(channel *Channel, client *Client) {
	target.NumericReply(ERR_USERNOTINCHANNEL,
		"%s %s :They aren't on that channel", client.Nick(), channel)
}

func (target *Client) ErrCannotSendToChan(channel *Channel) {
	target.NumericReply(ERR_CANNOTSENDTOCHAN,
		"%s :Cannot send to channel", channel)
}

// <channel> :You're not channel operator
func (target *Client) ErrChanOPrivIsNeeded(channel *Channel) {
	target.NumericReply(ERR_CHANOPRIVSNEEDED,
		"%s :You're not channel operator", channel)
}

func (target *Client) ErrNoMOTD() {
	target.NumericReply(ERR_NOMOTD, ":MOTD File is missing")
}

func (target *Client) ErrNoNicknameGiven() {
	target.NumericReply(ERR_NONICKNAMEGIVEN, ":No nickname given")
}

func (target *Client) ErrErroneusNickname(nick string) {
	target.NumericReply(ERR_ERRONEUSNICKNAME,
		"%s :Erroneous nickname", nick)
}
