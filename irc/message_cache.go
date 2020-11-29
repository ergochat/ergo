// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"time"

	"github.com/goshuirc/irc-go/ircmsg"

	"github.com/oragono/oragono/irc/caps"
	"github.com/oragono/oragono/irc/utils"
)

// MessageCache caches serialized IRC messages.
// First call Initialize or InitializeSplitMessage, which records
// the parameters and builds the cache. Then call Send, which will
// either send a cached version of the message or dispatch to another
// send routine that can synthesize the necessary version on the fly.
type MessageCache struct {
	// these cache a single-line message (e.g., JOIN, or PRIVMSG with a 512-byte message)
	// one version is "plain" (legacy clients with no tags) and one is "full" (client has
	// the message-tags cap)
	plain    []byte
	fullTags []byte
	// these cache a multiline message (a PRIVMSG that was sent as a multiline batch)
	// one version is "plain" (legacy clients with no tags) and one is "full" (client has
	// the multiline cap)
	plainMultiline    [][]byte
	fullTagsMultiline [][]byte

	time        time.Time
	msgid       string
	accountName string
	tags        map[string]string
	source      string
	command     string

	params []string

	target       string
	splitMessage utils.SplitMessage
}

func addAllTags(msg *ircmsg.IrcMessage, tags map[string]string, serverTime time.Time, msgid, accountName string) {
	msg.UpdateTags(tags)
	msg.SetTag("time", serverTime.Format(IRCv3TimestampFormat))
	if accountName != "*" {
		msg.SetTag("account", accountName)
	}
	if msgid != "" {
		msg.SetTag("msgid", msgid)
	}
}

func (m *MessageCache) handleErr(server *Server, err error) bool {
	if err != nil {
		server.logger.Error("internal", "Error assembling message for sending", err.Error())
		// blank these out so Send will be a no-op
		m.fullTags = nil
		m.fullTagsMultiline = nil
		return true
	}
	return false
}

func (m *MessageCache) Initialize(server *Server, serverTime time.Time, msgid string, nickmask, accountName string, tags map[string]string, command string, params ...string) (err error) {
	m.time = serverTime
	m.msgid = msgid
	m.source = nickmask
	m.accountName = accountName
	m.tags = tags
	m.command = command
	m.params = params

	var msg ircmsg.IrcMessage
	config := server.Config()
	if config.Server.Compatibility.forceTrailing && commandsThatMustUseTrailing[command] {
		msg.ForceTrailing()
	}
	msg.Prefix = nickmask
	msg.Command = command
	msg.Params = make([]string, len(params))
	copy(msg.Params, params)
	m.plain, err = msg.LineBytesStrict(false, MaxLineLen)
	if m.handleErr(server, err) {
		return
	}

	addAllTags(&msg, tags, serverTime, msgid, accountName)
	m.fullTags, err = msg.LineBytesStrict(false, MaxLineLen)
	if m.handleErr(server, err) {
		return
	}
	return
}

func (m *MessageCache) InitializeSplitMessage(server *Server, nickmask, accountName string, tags map[string]string, command, target string, message utils.SplitMessage) (err error) {
	m.time = message.Time
	m.msgid = message.Msgid
	m.source = nickmask
	m.accountName = accountName
	m.tags = tags
	m.command = command
	m.target = target
	m.splitMessage = message

	config := server.Config()
	forceTrailing := config.Server.Compatibility.forceTrailing && commandsThatMustUseTrailing[command]

	if message.Is512() {
		isTagmsg := command == "TAGMSG"
		var msg ircmsg.IrcMessage
		if forceTrailing {
			msg.ForceTrailing()
		}

		msg.Prefix = nickmask
		msg.Command = command
		if isTagmsg {
			msg.Params = []string{target}
		} else {
			msg.Params = []string{target, message.Message}
		}
		m.params = msg.Params
		if !isTagmsg {
			m.plain, err = msg.LineBytesStrict(false, MaxLineLen)
			if m.handleErr(server, err) {
				return
			}
		}

		addAllTags(&msg, tags, message.Time, message.Msgid, accountName)
		m.fullTags, err = msg.LineBytesStrict(false, MaxLineLen)
		if m.handleErr(server, err) {
			return
		}
	} else {
		var msg ircmsg.IrcMessage
		if forceTrailing {
			msg.ForceTrailing()
		}
		msg.Prefix = nickmask
		msg.Command = command
		msg.Params = make([]string, 2)
		msg.Params[0] = target
		m.plainMultiline = make([][]byte, len(message.Split))
		for i, pair := range message.Split {
			msg.Params[1] = pair.Message
			m.plainMultiline[i], err = msg.LineBytesStrict(false, MaxLineLen)
			if m.handleErr(server, err) {
				return
			}
		}

		// we need to send the same batch ID to all recipient sessions;
		// use a uuidv4-alike to ensure that it won't collide
		batch := composeMultilineBatch(utils.GenerateSecretToken(), nickmask, accountName, tags, command, target, message)
		m.fullTagsMultiline = make([][]byte, len(batch))
		for i, msg := range batch {
			if forceTrailing {
				msg.ForceTrailing()
			}
			m.fullTagsMultiline[i], err = msg.LineBytesStrict(false, MaxLineLen)
			if m.handleErr(server, err) {
				return
			}
		}
	}
	return
}

func (m *MessageCache) Send(session *Session) {
	if m.fullTags != nil {
		if session.capabilities.Has(caps.MessageTags) {
			session.sendBytes(m.fullTags, false)
		} else if !(session.capabilities.Has(caps.ServerTime) || session.capabilities.Has(caps.AccountTag)) {
			if m.plain != nil {
				session.sendBytes(m.plain, false)
			}
		} else {
			session.sendFromClientInternal(false, m.time, m.msgid, m.source, m.accountName, nil, m.command, m.params...)
		}
	} else if m.fullTagsMultiline != nil {
		if session.capabilities.Has(caps.Multiline) {
			for _, line := range m.fullTagsMultiline {
				session.sendBytes(line, false)
			}
		} else if !(session.capabilities.Has(caps.ServerTime) || session.capabilities.Has(caps.AccountTag)) {
			for _, line := range m.plainMultiline {
				session.sendBytes(line, false)
			}
		} else {
			session.sendSplitMsgFromClientInternal(false, m.source, m.accountName, m.tags, m.command, m.target, m.splitMessage)
		}
	}
}
