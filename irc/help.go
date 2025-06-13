// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/ergochat/ergo/irc/languages"
)

// HelpEntryType represents the different sorts of help entries that can exist.
type HelpEntryType int

const (
	// CommandHelpEntry is a help entry explaining a client command.
	CommandHelpEntry HelpEntryType = iota
	// InformationHelpEntry is a help entry explaining general server info.
	InformationHelpEntry
	// ISupportHelpEntry is a help entry explaining a specific RPL_ISUPPORT token.
	ISupportHelpEntry
)

// HelpEntry represents an entry in the Help map.
type HelpEntry struct {
	oper          bool
	text          string
	textGenerator func(*Client) string
	helpType      HelpEntryType
	duplicate     bool
}

// used for duplicates
var (
	cmodeHelpText = `== Channel Modes ==

Ergo supports the following channel modes:

  +b  |  Client masks that are banned from the channel (e.g. *!*@127.0.0.1)
  +e  |  Client masks that are exempted from bans.
  +I  |  Client masks that are exempted from the invite-only flag.
  +i  |  Invite-only mode, only invited clients can join the channel.
  +k  |  Key required when joining the channel.
  +l  |  Client join limit for the channel.
  +f  |  Users who are unable to join this channel (due to another mode) are forwarded
         to the provided channel instead.
  +m  |  Moderated mode, only privileged clients can talk on the channel.
  +n  |  No-outside-messages mode, only users that are on the channel can send
      |  messages to it.
  +R  |  Only registered users can join the channel.
  +M  |  Only registered or voiced users can speak in the channel.
  +s  |  Secret mode, channel won't show up in /LIST or whois replies.
  +t  |  Only channel opers can modify the topic.
  +E  |  Roleplaying commands are enabled in the channel.
  +C  |  Clients are blocked from sending CTCP messages in the channel.
  +u  |  Auditorium mode: JOIN, PART, QUIT, NAMES, and WHO are hidden
         from unvoiced clients.
  +U  |  Op-moderated mode: messages from unprivileged clients are sent
         only to channel operators.

= Prefixes =

  +q (~)  |  Founder channel mode.
  +a (&)  |  Admin channel mode.
  +o (@)  |  Operator channel mode.
  +h (%)  |  Halfop channel mode.
  +v (+)  |  Voice channel mode.`
	umodeHelpText = `== User Modes ==

Ergo supports the following user modes:

  +a  |  User is marked as being away. This mode is set with the /AWAY command.
  +i  |  User is marked as invisible (their channels are hidden from whois replies).
  +o  |  User is an IRC operator.
  +R  |  User only accepts messages from other registered users.
  +s  |  Server Notice Masks (see help with /HELPOP snomasks).
  +Z  |  User is connected via TLS.
  +B  |  User is a bot.
  +E  |  User can receive roleplaying commands.
  +T  |  CTCP messages to the user are blocked.`
	snomaskHelpText = `== Server Notice Masks ==

Ergo supports the following server notice masks for operators:

  a  |  Local announcements.
  c  |  Local client connections.
  d  |  Local client disconnects.
  j  |  Local channel actions.
  k  |  Local kills.
  n  |  Local nick changes.
  o  |  Local oper actions.
  q  |  Local quits.
  t  |  Local /STATS usage.
  u  |  Local client account actions.
  x  |  Local X-lines (DLINE/KLINE/etc).
  v  |  Local vhost changes.

To set a snomask, do this with your nickname:

  /MODE <nick> +s <chars>

For instance, this would set the kill, oper, account and xline snomasks on dan:

  /MODE dan +s koux`
)

// Help contains the help strings distributed with the IRCd.
var Help = map[string]HelpEntry{
	// Commands
	"accept": {
		text: `ACCEPT <target>

ACCEPT allows the target user to send you direct messages, overriding any
restrictions that might otherwise prevent this. Currently, the only
applicable restriction is the +R registered-only mode.`,
	},
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
	"batch": {
		text: `BATCH {+,-}reference-tag type [params...]

BATCH initiates an IRCv3 client-to-server batch. You should never need to
issue this command manually.`,
	},
	"cap": {
		text: `CAP <subcommand> [:<capabilities>]

Used in capability negotiation. See the IRCv3 specs for more info:
http://ircv3.net/specs/core/capability-negotiation-3.1.html
http://ircv3.net/specs/core/capability-negotiation-3.2.html`,
	},
	"chathistory": {
		text: `CHATHISTORY [params]

CHATHISTORY is a history replay command associated with the IRCv3
chathistory extension. See this document:
https://ircv3.net/specs/extensions/chathistory`,
	},
	"debug": {
		oper: true,
		text: `DEBUG <option>

Provides various debugging commands for the IRCd. <option> can be one of:

* GCSTATS: Garbage control statistics.
* NUMGOROUTINE: Number of goroutines in use.
* STARTCPUPROFILE: Starts the CPU profiler.
* STOPCPUPROFILE: Stops the CPU profiler.
* PROFILEHEAP: Writes a memory profile.
* CRASHSERVER: Crashes the server (for use in failover testing)`,
	},
	"defcon": {
		oper: true,
		text: `DEFCON [level]

The DEFCON system can disable server features at runtime, to mitigate
spam or other hostile activity. It has five levels, which are cumulative
(i.e., level 3 includes all restrictions from level 4 and so on):

5: Normal operation
4: No new account or channel registrations; if Tor is enabled, no new
   unauthenticated connections from Tor
3: All users are +R; no changes to vhosts
2: No new unauthenticated connections; all channels are +R
1: No new connections except from localhost or other trusted IPs`,
	},
	"deoper": {
		oper: true,
		text: `DEOPER

DEOPER removes the IRCop privileges granted to you by a successful /OPER.`,
	},
	"dline": {
		oper: true,
		text: `DLINE [ANDKILL] [MYSELF] [duration] <ip>/<net> [ON <server>] [reason [| oper reason]]
DLINE LIST

Bans an IP address or network from connecting to the server. If the duration is
given then only for that long. The reason is shown to the user themselves, but
everyone else will see a standard message. The oper reason is shown to
operators getting info about the DLINEs that exist.

Bans are saved across subsequent launches of the server.

"ANDKILL" means that all matching clients are also removed from the server.

"MYSELF" is required when the DLINE matches the address the person applying it is connected
from. If "MYSELF" is not given, trying to DLINE yourself will result in an error.

[duration] can be of the following forms:
	1y 12mo 31d 10h 8m 13s

<net> is specified in typical CIDR notation. For example:
	127.0.0.1/8
	8.8.8.8/24

ON <server> specifies that the ban is to be set on that specific server.

[reason] and [oper reason], if they exist, are separated by a vertical bar (|).

If "DLINE LIST" is sent, the server sends back a list of our current DLINEs.

To remove a DLINE, use the "UNDLINE" command.`,
	},
	"extjwt": {
		text: `EXTJWT <target> [service_name]

Get a JSON Web Token for target (either * or a channel name).`,
	},
	"help": {
		text: `HELP <argument>

Get an explanation of <argument>, or "index" for a list of help topics.`,
	},
	"helpop": {
		text: `HELPOP <argument>

Get an explanation of <argument>, or "index" for a list of help topics.`,
	},
	"history": {
		text: `HISTORY <target> [limit]

Replay message history. <target> can be a channel name, "me" to replay direct
message history, or a nickname to replay another client's direct message
history (they must be logged into the same account as you). [limit] can be
either an integer (the maximum number of messages to replay), or a time
duration like 10m or 1h (the time window within which to replay messages).`,
	},
	"info": {
		text: `INFO

Sends information about the server, developers, etc.`,
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
	"isupport": {
		text: `ISUPPORT

Returns RPL_ISUPPORT lines describing the server's capabilities.`,
	},
	"join": {
		text: `JOIN <channel>{,<channel>} [<key>{,<key>}]

Joins the given channels with the matching keys.`,
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
		text: `KLINE [ANDKILL] [MYSELF] [duration] <mask> [ON <server>] [reason [| oper reason]]
KLINE LIST

Bans a mask from connecting to the server. If the duration is given then only for that
long. The reason is shown to the user themselves, but everyone else will see a standard
message. The oper reason is shown to operators getting info about the KLINEs that exist.

Bans are saved across subsequent launches of the server.

"ANDKILL" means that all matching clients are also removed from the server.

"MYSELF" is required when the KLINE matches the address the person applying it is connected
from. If "MYSELF" is not given, trying to KLINE yourself will result in an error.

[duration] can be of the following forms:
	1y 12mo 31d 10h 8m 13s

<mask> is specified in typical IRC format. For example:
	dan
	dan!5*@127.*

ON <server> specifies that the ban is to be set on that specific server.

[reason] and [oper reason], if they exist, are separated by a vertical bar (|).

If "KLINE LIST" is sent, the server sends back a list of our current KLINEs.

To remove a KLINE, use the "UNKLINE" command.`,
	},
	"language": {
		text: `LANGUAGE <code>{ <code>}

Sets your preferred languages to the given ones.`,
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
	"markread": {
		text: `MARKREAD <target> [timestamp]

MARKREAD updates an IRCv3 read message marker. It is not intended for use by
end users. For more details, see the latest draft of the read-marker
specification.`,
	},
	"metadata": {
		text: `METADATA <target> <subcommand> [<everything else>...]
		
Retrieve and meddle with metadata for the given target.
Have a look at https://ircv3.net/specs/extensions/metadata for interesting technical information.`,
	},
	"mode": {
		text: `MODE <target> [<modestring> [<mode arguments>...]]

Sets and removes modes from the given target. For more specific information on
mode characters, see the help for "modes".`,
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
		text: `OPER <name> [password]

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
	"persistence": {
		text: `PERSISTENCE [params]

PERSISTENCE is a command associated with an IRC protocol extension for
persistent connections. End users should probably use /NS GET ALWAYS-ON
and /NS SET ALWAYS-ON instead.`,
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
	"redact": {
		text: `REDACT <target> <targetmsgid> [<reason>]

Removes the message of the target msgid from the chat history of a channel
or target user.`,
	},
	"relaymsg": {
		text: `RELAYMSG <channel> <spoofed nick> :<message>

This command lets channel operators relay messages to their
channel from other messaging systems using relay bots. The
spoofed nickname MUST contain a forwardslash.

For example:
	RELAYMSG #ircv3 Mallory/D :Welp, we linked Discord...`,
	},
	"rename": {
		text: `RENAME <channel> <newname> [<reason>]

Renames the given channel with the given reason, if possible.

For example:
	RENAME #ircv2 #ircv3 :Protocol upgrades!`,
	},
	"sajoin": {
		oper: true,
		text: `SAJOIN [nick] #channel{,#channel}

Forcibly joins a user to a channel, ignoring restrictions like bans, user limits
and channel keys. If [nick] is omitted, it defaults to the operator.`,
	},
	"sanick": {
		oper: true,
		text: `SANICK <currentnick> <newnick>

Gives the given user a new nickname.`,
	},
	"samode": {
		oper: true,
		text: `SAMODE <target> [<modestring> [<mode arguments>...]]

Forcibly sets and removes modes from the given target -- only available to
opers. For more specific information on mode characters, see the help for
"cmode" and "umode".`,
	},
	"scene": {
		text: `SCENE <target> <text to be sent>

The SCENE command is used to send a scene notification to the given target.`,
	},
	"setname": {
		text: `SETNAME <realname>

The SETNAME command updates the realname to be the newly-given one.`,
	},
	"summon": {
		text: `SUMMON [parameters]

The SUMMON command is not implemented.`,
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
	"register": {
		text: `REGISTER <account> <email | *> <password>

Registers an account in accordance with the draft/account-registration capability.`,
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
	"uban": {
		text: `UBAN <subcommand> [arguments]

Ergo's "unified ban" system. Accepts the following subcommands:

1. UBAN ADD <target> [REQUIRE-SASL] [DURATION <duration>] [REASON...]
2. UBAN DEL <target>
3. UBAN LIST
4. UBAN INFO <target>

<target> may be an IP, a CIDR, a nickmask with wildcards, or the name of an
account to suspend. Note that REQUIRE-SASL is only valid for IP and CIDR bans.`,
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
	"uninvite": {
		text: `UNINVITE <nickname> <channel>

UNINVITE rescinds a channel invitation sent for an invite-only channel.`,
	},
	"users": {
		text: `USERS [parameters]

The USERS command is not implemented.`,
	},
	"userhost": {
		text: `USERHOST <nickname>{ <nickname>}
		
Shows information about the given users. Takes up to 10 nicknames.`,
	},
	"verify": {
		text: `VERIFY <account> <code>

Verifies an account in accordance with the draft/account-registration capability.`,
	},
	"version": {
		text: `VERSION [server]

Views the version of software and the RPL_ISUPPORT tokens for the given server.`,
	},
	"webirc": {
		oper: true, // not really, but it's restricted anyways
		text: `WEBIRC <password> <gateway> <hostname> <ip> [:<flags>]

Used by web<->IRC gateways and bouncers, the WEBIRC command allows gateways to
pass-through the real IP addresses of clients:
ircv3.net/specs/extensions/webirc.html

<flags> is a list of space-separated strings indicating various details about
the connection from the client to the gateway, such as:

- tls: this flag indicates that the client->gateway connection is secure`,
	},
	"webpush": {
		text: `WEBPUSH <subcommand> [arguments]

Configures web push settings. Not for direct use by end users.`,
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
	"znc": {
		text: `ZNC <module> [params]

Used to emulate features of the ZNC bouncer. This command is not intended
for direct use by end users.`,
		duplicate: true,
	},

	// Informational
	"modes": {
		textGenerator: modesTextGenerator,
		helpType:      InformationHelpEntry,
	},
	"cmode": {
		text:     cmodeHelpText,
		helpType: InformationHelpEntry,
	},
	"cmodes": {
		text:      cmodeHelpText,
		helpType:  InformationHelpEntry,
		duplicate: true,
	},
	"umode": {
		text:     umodeHelpText,
		helpType: InformationHelpEntry,
	},
	"umodes": {
		text:      umodeHelpText,
		helpType:  InformationHelpEntry,
		duplicate: true,
	},
	"snomask": {
		text:      snomaskHelpText,
		helpType:  InformationHelpEntry,
		oper:      true,
		duplicate: true,
	},
	"snomasks": {
		text:     snomaskHelpText,
		helpType: InformationHelpEntry,
		oper:     true,
	},

	// RPL_ISUPPORT
	"casemapping": {
		text: `RPL_ISUPPORT CASEMAPPING

Ergo supports an experimental unicode casemapping designed for extended
Unicode support. This casemapping is based off RFC 7613 and the draft rfc7613
casemapping spec here: https://ergo.chat/specs.html`,
		helpType: ISupportHelpEntry,
	},
	"prefix": {
		text: `RPL_ISUPPORT PREFIX

Ergo supports the following channel membership prefixes:

  +q (~)  |  Founder channel mode.
  +a (&)  |  Admin channel mode.
  +o (@)  |  Operator channel mode.
  +h (%)  |  Halfop channel mode.
  +v (+)  |  Voice channel mode.`,
		helpType: ISupportHelpEntry,
	},
}

// modesTextGenerator generates the text for the 'modes' help entry.
// it exists only so we can translate this entry appropriately.
func modesTextGenerator(client *Client) string {
	return client.t(cmodeHelpText) + "\n\n" + client.t(umodeHelpText)
}

type HelpIndexManager struct {
	sync.RWMutex // tier 1

	langToIndex     map[string]string
	langToOperIndex map[string]string
}

// GenerateHelpIndex is used to generate HelpIndex.
// Returns: a map from language code to the help index in that language.
func GenerateHelpIndex(lm *languages.Manager, forOpers bool) map[string]string {
	// generate the help entry lists
	var commands, isupport, information []string

	var line string
	for name, info := range Help {
		if info.duplicate {
			continue
		}
		if info.oper && !forOpers {
			continue
		}

		line = fmt.Sprintf("   %s", name)

		if info.helpType == CommandHelpEntry {
			commands = append(commands, line)
		} else if info.helpType == ISupportHelpEntry {
			isupport = append(isupport, line)
		} else if info.helpType == InformationHelpEntry {
			information = append(information, line)
		}
	}

	// create the strings
	sort.Strings(commands)
	commandsString := strings.Join(commands, "\n")
	sort.Strings(isupport)
	isupportString := strings.Join(isupport, "\n")
	sort.Strings(information)
	informationString := strings.Join(information, "\n")

	// sub them in
	defaultHelpIndex := `= Help Topics =

Commands:
%[1]s

RPL_ISUPPORT Tokens:
%[2]s

Information:
%[3]s`

	newHelpIndex := make(map[string]string)

	newHelpIndex["en"] = fmt.Sprintf(defaultHelpIndex, commandsString, isupportString, informationString)

	for langCode := range lm.Languages {
		translatedHelpIndex := lm.Translate([]string{langCode}, defaultHelpIndex)
		if translatedHelpIndex != defaultHelpIndex {
			newHelpIndex[langCode] = fmt.Sprintf(translatedHelpIndex, commandsString, isupportString, informationString)
		}
	}

	return newHelpIndex
}

// GenerateIndices regenerates our help indexes for each currently enabled language.
func (hm *HelpIndexManager) GenerateIndices(lm *languages.Manager) {
	// generate help indexes
	langToIndex := GenerateHelpIndex(lm, false)
	langToOperIndex := GenerateHelpIndex(lm, true)

	hm.Lock()
	defer hm.Unlock()
	hm.langToIndex = langToIndex
	hm.langToOperIndex = langToOperIndex
}

// sendHelp sends the client help of the given string.
func (client *Client) sendHelp(helpEntry string, text string, rb *ResponseBuffer) {
	helpEntry = strings.ToUpper(helpEntry)
	nick := client.Nick()
	textLines := strings.Split(text, "\n")

	for i, line := range textLines {
		if i == 0 {
			rb.Add(nil, client.server.name, RPL_HELPSTART, nick, helpEntry, line)
		} else {
			rb.Add(nil, client.server.name, RPL_HELPTXT, nick, helpEntry, line)
		}
	}
	rb.Add(nil, client.server.name, RPL_ENDOFHELP, nick, helpEntry, client.t("End of /HELPOP"))
}

// GetHelpIndex returns the help index for the given language.
func (hm *HelpIndexManager) GetIndex(languages []string, oper bool) string {
	hm.RLock()
	langToIndex := hm.langToIndex
	if oper {
		langToIndex = hm.langToOperIndex
	}
	hm.RUnlock()

	for _, lang := range languages {
		index, exists := langToIndex[lang]
		if exists {
			return index
		}
	}
	// 'en' always exists
	return langToIndex["en"]
}

func init() {
	// startup check that we have HELP entries for every command
	for name := range Commands {
		_, exists := Help[strings.ToLower(name)]
		if !exists {
			panic(fmt.Sprintf("Help entry does not exist for command %s", name))
		}
	}
}
