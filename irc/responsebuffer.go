// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"time"

	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/oragono/oragono/irc/caps"
)

// ResponseBuffer - put simply - buffers messages and then outputs them to a given client.
//
// Using a ResponseBuffer lets you really easily implement labeled-response, since the
// buffer will silently create a batch if required and label the outgoing messages as
// necessary (or leave it off and simply tag the outgoing message).
type ResponseBuffer struct {
	Label    string
	target   *Client
	messages []ircmsg.IrcMessage
}

// GetLabel returns the label from the given message.
func GetLabel(msg ircmsg.IrcMessage) string {
	return msg.Tags["label"].Value
}

// NewResponseBuffer returns a new ResponseBuffer.
func NewResponseBuffer(target *Client) *ResponseBuffer {
	return &ResponseBuffer{
		target: target,
	}
}

// Add adds a standard new message to our queue.
func (rb *ResponseBuffer) Add(tags *map[string]ircmsg.TagValue, prefix string, command string, params ...string) {
	message := ircmsg.MakeMessage(tags, prefix, command, params...)

	rb.messages = append(rb.messages, message)
}

// AddFromClient adds a new message from a specific client to our queue.
func (rb *ResponseBuffer) AddFromClient(msgid string, from *Client, tags *map[string]ircmsg.TagValue, command string, params ...string) {
	// attach account-tag
	if rb.target.capabilities.Has(caps.AccountTag) && from.account != &NoAccount {
		if tags == nil {
			tags = ircmsg.MakeTags("account", from.account.Name)
		} else {
			(*tags)["account"] = ircmsg.MakeTagValue(from.account.Name)
		}
	}
	// attach message-id
	if len(msgid) > 0 && rb.target.capabilities.Has(caps.MessageTags) {
		if tags == nil {
			tags = ircmsg.MakeTags("draft/msgid", msgid)
		} else {
			(*tags)["draft/msgid"] = ircmsg.MakeTagValue(msgid)
		}
	}

	rb.Add(tags, from.nickMaskString, command, params...)
}

// AddSplitMessageFromClient adds a new split message from a specific client to our queue.
func (rb *ResponseBuffer) AddSplitMessageFromClient(msgid string, from *Client, tags *map[string]ircmsg.TagValue, command string, target string, message SplitMessage) {
	if rb.target.capabilities.Has(caps.MaxLine) {
		rb.AddFromClient(msgid, from, tags, command, target, message.ForMaxLine)
	} else {
		for _, str := range message.For512 {
			rb.AddFromClient(msgid, from, tags, command, target, str)
		}
	}
}

// Send sends the message to our target client.
func (rb *ResponseBuffer) Send() error {
	// fall out if no messages to send
	if len(rb.messages) == 0 {
		return nil
	}

	// make batch and all if required
	var batch *Batch
	useLabel := rb.target.capabilities.Has(caps.LabeledResponse) && rb.Label != ""
	if useLabel && 1 < len(rb.messages) && rb.target.capabilities.Has(caps.Batch) {
		batch = rb.target.server.batches.New("draft/labeled-response")
	}

	// if label but no batch, add label to first message
	if useLabel && batch == nil {
		message := rb.messages[0]
		message.Tags["label"] = ircmsg.MakeTagValue(rb.Label)
		rb.messages[0] = message
	}

	// start batch if required
	if batch != nil {
		batch.Start(rb.target, ircmsg.MakeTags("label", rb.Label))
	}

	// send each message out
	for _, message := range rb.messages {
		// attach server-time if needed
		if rb.target.capabilities.Has(caps.ServerTime) {
			t := time.Now().UTC().Format("2006-01-02T15:04:05.999Z")
			message.Tags["time"] = ircmsg.MakeTagValue(t)
		}

		// attach batch ID
		if batch != nil {
			message.Tags["batch"] = ircmsg.MakeTagValue(batch.ID)
		}

		// send message out
		rb.target.SendRawMessage(message)
	}

	// end batch if required
	if batch != nil {
		batch.End(rb.target)
	}

	// clear out any existing messages
	rb.messages = []ircmsg.IrcMessage{}

	return nil
}

// Notice sends the client the given notice from the server.
func (rb *ResponseBuffer) Notice(text string) {
	rb.Add(nil, rb.target.server.name, "NOTICE", rb.target.nick, text)
}
