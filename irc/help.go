// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"strings"

	"github.com/DanielOaks/girc-go/ircmsg"
)

// HelpEntry represents an entry in the Help map.
type HelpEntry struct {
	oper bool
	text string
}

// used for duplicates
var (
	cmodeHelpText = `== Channel Modes ==

Oragono supports the following channel modes:

= Type A - list modes =

  +b  |  Client masks that are banned from the channel.
  +e  |  Client masks that are exempted from bans.
  +I  |  Client masks that are exempted from the invite-only flag.

= Type C - setting modes with a parameter =

  +l  |  Client join limit for the channel.
  +k  |  Key required when joining the channel.

= Type D - flag modes =

  +i  |  Invite-only mode, only invited clients can join the channel.
  +m  |  Moderated mode, only privileged clients can talk on the channel.
  +n  |  No-outside-messages mode, only users that are on the channel can send
      |  messages to it.
  +t  |  Only channel opers can modify the topic.
  +s  |  Secret mode, channel won't show up in /LIST or whois replies.

= Prefixes =

  +q (~)  |  Founder channel mode.
  +a (&)  |  Admin channel mode.
  +o (@)  |  Operator channel mode.
  +h (%)  |  Halfop channel mode.
  +v (+)  |  Voice channel mode.`
	umodeHelpText = `== User Modes ==

Oragono supports the following user modes:

  +a  |  User is marked as being away. This mode is set with the /AWAY command.
  +i  |  User is marked as invisible (their channels are hidden from whois replies).
  +o  |  User is an IRC operator.
  +Z  |  User is connected via TLS.`
)

// Help contains the help strings distributed with the IRCd.
var Help = map[string]HelpEntry{
	// Commands
	"ambiance": {
		text: `AMBIANCE <target> <text to be sent>

The AMBIANCE command is used to send a scene notification to the given target.`,
	},
	"authenticate": {
		text: `AUTHENTICATE

Used during SASL authentication. See the IRCv3 specs for more info:
http://ircv3.net/specs/extensions/sasl-3.1.html`,
	},
	"away": {
		text: `AWAY [message]

If [message] is sent, marks you away. If [message] is not sent, marks you no
longer away.`,
	},
	"cap": {
		text: `CAP <subcommand> [:<capabilities>]

Used in capability negotiation. See the IRCv3 specs for more info:
http://ircv3.net/specs/core/capability-negotiation-3.1.html
http://ircv3.net/specs/core/capability-negotiation-3.2.html`,
	},
	"debug": {
		oper: true,
		text: `DEBUG <option>

Prints debug information about the IRCd. <option> can be one of:

* GCSTATS: Garbage control statistics.
* NUMGOROUTINE: Number of goroutines in use.
* STARTCPUPROFILE: Starts the CPU profiler.
* STOPCPUPROFILE: Stops the CPU profiler.
* PROFILEHEAP: Writes out the CPU profiler info.`,
	},
	"dline": {
		oper: true,
		text: `DLINE [MYSELF] [duration] <ip>/<net> [ON <server>] [reason [| oper reason]]

Bans an IP address or network from connecting to the server. If the duration is
given then only for that long. The reason is shown to the user themselves, but
everyone else will see a standard message. The oper reason is shown to
operators getting info about the DLINEs that exist.

Bans are saved across subsequent launches of the server.

"MYSELF" is required when the DLINE matches the address the person applying it is connected
from. If "MYSELF" is not given, trying to DLINE yourself will result in an error.

[duration] can be of the following forms:
	10h 8m 13s

<net> is specified in typical CIDR notation. For example:
	127.0.0.1/8
	8.8.8.8/24

ON <server> specifies that the ban is to be set on that specific server.

[reason] and [oper reason], if they exist, are separated by a vertical bar (|).`,
	},
	"help": {
		text: `HELP <argument>

Get an explanation of <argument>.`,
	},
	"invite": {
		text: `INVITE <nickname> <channel>

Invites the given user to the given channel, so long as you have the
appropriate channel privs.`,
	},
	"ison": {
		text: `ISON <nickname>{ <nickname>}

Returns whether the given nicks exist on the network.`,
	},
	"join": {
		text: `JOIN <channel>{,<channel>} [<key>{,<key>}]
JOIN 0

Joins the given channels with the matching keys, or if the only param is "0"
parts all channels instead.`,
	},
	"kick": {
		text: `KICK <channel> <user> [reason]

Removes the user from the given channel, so long as you have the appropriate
channel privs.`,
	},
	"kill": {
		oper: true,
		text: `KILL <nickname> [reason]

Removes the given user from the network, showing them the reason if it is
supplied.`,
	},
	"kline": {
		oper: true,
		text: `KLINE [MYSELF] [duration] <mask> [ON <server>] [reason [| oper reason]]

Bans a mask from connecting to the server. If the duration is given then only for that
long. The reason is shown to the user themselves, but everyone else will see a standard
message. The oper reason is shown to operators getting info about the KLINEs that exist.

Bans are saved across subsequent launches of the server.

"MYSELF" is required when the KLINE matches the address the person applying it is connected
from. If "MYSELF" is not given, trying to KLINE yourself will result in an error.

[duration] can be of the following forms:
	10h 8m 13s

<mask> is specified in typical IRC format. For example:
	dan
	dan!5*@127.*

ON <server> specifies that the ban is to be set on that specific server.

[reason] and [oper reason], if they exist, are separated by a vertical bar (|).`,
	},
	"list": {
		text: `LIST [<channel>{,<channel>}] [<elistcond>{,<elistcond>}]

Shows information on the given channels (or if none are given, then on all
channels). <elistcond>s modify how the channels are selected.`,
		//TODO(dan): Explain <elistcond>s in more specific detail
	},
	"lusers": {
		text: `LUSERS [<mask> [<server>]]

Shows statistics about the size of the network. If <mask> is given, only
returns stats for servers matching the given mask.  If <server> is given, the
command is processed by that server.`,
	},
	"mode": {
		text: `MODE <target> [<modestring> [<mode arguments>...]]

Sets and removes modes from the given target. For more specific information on
mode characters, see the help for "cmode" and "umode".`,
	},
	"monitor": {
		text: `MONITOR <subcmd>

Allows the monitoring of nicknames, for alerts when they are online and
offline. The subcommands are:

    MONITOR + target{,target}
Adds the given names to your list of monitored nicknames.

    MONITOR - target{,target}
Removes the given names from your list of monitored nicknames.

    MONITOR C
Clears your list of monitored nicknames.

    MONITOR L
Lists all the nicknames you are currently monitoring.

    MONITOR S
Lists whether each nick in your MONITOR list is online or offline.`,
	},
	"motd": {
		text: `MOTD [server]

Returns the message of the day for this, or the given, server.`,
	},
	"names": {
		text: `NAMES [<channel>{,<channel>}]

Views the clients joined to a channel and their channel membership prefixes. To
view the channel membership prefixes supported by this server, see the help for
"PREFIX".`,
	},
	"nick": {
		text: `NICK <newnick>

Sets your nickname to the new given one.`,
	},
	"notice": {
		text: `NOTICE <target>{,<target>} <text to be sent>

Sends the text to the given targets as a NOTICE.`,
	},
	"npc": {
		text: `NPC <target> <sourcenick> <text to be sent>
		
The NPC command is used to send a message to the target as the source.

Requires the roleplay mode (+E) to be set on the target.`,
	},
	"npca": {
		text: `NPCA <target> <sourcenick> <text to be sent>
		
The NPC command is used to send an action to the target as the source.

Requires the roleplay mode (+E) to be set on the target.`,
	},
	"oper": {
		text: `OPER <name> <password>

If the correct details are given, gives you IRCop privs.`,
	},
	"part": {
		text: `PART <channel>{,<channel>} [reason]

Leaves the given channels and shows people the given reason.`,
	},
	"pass": {
		text: `PASS <password>

When the server requires a connection password to join, used to send us the
password.`,
	},
	"ping": {
		text: `PING <args>...

Requests a PONG. Used to check link connectivity.`,
	},
	"pong": {
		text: `PONG <args>...

Replies to a PING. Used to check link connectivity.`,
	},
	"privmsg": {
		text: `PRIVMSG <target>{,<target>} <text to be sent>

Sends the text to the given targets as a PRIVMSG.`,
	},
	"sanick": {
		oper: true,
		text: `SANICK <currentnick> <newnick>

Gives the given user a new nickname.`,
	},
	"scene": {
		text: `SCENE <target> <text to be sent>

The SCENE command is used to send a scene notification to the given target.`,
	},
	"tagmsg": {
		text: `@+client-only-tags TAGMSG <target>{,<target>}

Sends the given client-only tags to the given targets as a TAGMSG. See the IRCv3
specs for more info: http://ircv3.net/specs/core/message-tags-3.3.html`,
	},
	"quit": {
		text: `QUIT [reason]

Indicates that you're leaving the server, and shows everyone the given reason.`,
	},
	"reg": {
		text: `REG CREATE <accountname> [callback_namespace:]<callback> [cred_type] :<credential>
REG VERIFY <accountname> <auth_code>

Used in account registration. See the relevant specs for more info:
http://oragono.io/specs.html`,
	},
	"rehash": {
		oper: true,
		text: `REHASH

Reloads the config file and updates TLS certificates on listeners`,
	},
	"time": {
		text: `TIME [server]

Shows the time of the current, or the given, server.`,
	},
	"topic": {
		text: `TOPIC <channel> [topic]

If [topic] is given, sets the topic in the channel to that. If [topic] is not
given, views the current topic on the channel.`,
	},
	"undline": {
		oper: true,
		text: `UNDLINE <ip>/<net>

Removes an existing ban on an IP address or a network.

<net> is specified in typical CIDR notation. For example:
	127.0.0.1/8
	8.8.8.8/24`,
	},
	"unkline": {
		oper: true,
		text: `UNKLINE <mask>

Removes an existing ban on a mask.

For example:
	dan
	dan!5*@127.*`,
	},
	"user": {
		text: `USER <username> 0 * <realname>

Used in connection registration, sets your username and realname to the given
values (though your username may also be looked up with Ident).`,
	},
	"version": {
		text: `VERSION [server]

Views the version of software and the RPL_ISUPPORT tokens for the given server.`,
	},
	"who": {
		text: `WHO <name> [o]

Returns information for the given user.`,
	},
	"whois": {
		text: `WHOIS <client>{,<client>}

Returns information for the given user(s).`,
	},
	"whowas": {
		text: `WHOWAS <nickname>

Returns historical information on the last user with the given nickname.`,
	},

	// Informational
	"cmode": {
		text: cmodeHelpText,
	},
	"cmodes": {
		text: cmodeHelpText,
	},
	"umode": {
		text: umodeHelpText,
	},
	"umodes": {
		text: umodeHelpText,
	},

	// RPL_ISUPPORT
	"casemapping": {
		text: `RPL_ISUPPORT CASEMAPPING

Oragono supports an experimental unicode casemapping designed for extended
Unicode support. This casemapping is based off RFC 7613 and the draft rfc7613
casemapping spec here: http://oragono.io/specs.html`,
	},
	"prefix": {
		text: `RPL_ISUPPORT PREFIX

Oragono supports the following channel membership prefixes:

  +q (~)  |  Founder channel mode.
  +a (&)  |  Admin channel mode.
  +o (@)  |  Operator channel mode.
  +h (%)  |  Halfop channel mode.
  +v (+)  |  Voice channel mode.`,
	},
}

// sendHelp sends the client help of the given string.
func (client *Client) sendHelp(name string, text string) {
	splitName := strings.Split(name, " ")
	textLines := strings.Split(text, "\n")

	for i, line := range textLines {
		args := splitName
		args = append(args, line)
		if i == 0 {
			client.Send(nil, client.server.name, RPL_HELPSTART, args...)
		} else {
			client.Send(nil, client.server.name, RPL_HELPTXT, args...)
		}
	}
	args := splitName
	args = append(args, "End of /HELP")
	client.Send(nil, client.server.name, RPL_ENDOFHELP, args...)
}

// helpHandler returns the appropriate help for the given query.
func helpHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	argument := strings.ToLower(strings.TrimSpace(strings.Join(msg.Params, " ")))

	if len(argument) < 1 {
		client.sendHelp("HELP", `HELP <argument>

Get an explanation of <argument>.`)
		return false
	}

	helpHandler, exists := Help[argument]

	if exists && (!helpHandler.oper || (helpHandler.oper && client.flags[Operator])) {
		client.sendHelp(strings.ToUpper(argument), helpHandler.text)
	} else {
		args := msg.Params
		args = append(args, "Help not found")
		client.Send(nil, server.name, ERR_HELPNOTFOUND, args...)
	}

	return false
}
