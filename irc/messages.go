// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

// Message represents an internal message passed by oragono.
type Message struct {
	Type MessageType
	Verb MessageVerb
	Info map[MessageInfoKey]interface{}
}

// NewMessage returns a new Message.
// This is purely a convenience function.
func NewMessage(mt MessageType, mv MessageVerb) Message {
	var message Message
	message.Type = mt
	message.Verb = mv
	message.Info = make(map[MessageInfoKey]interface{})
	return message
}

// MessageType represents the type of message it is.
type MessageType int

const (
	// LineMT represents an IRC line Message Type
	LineMT MessageType = iota
)

// MessageVerb represents the verb (i.e. the specific command, etc) of a message.
type MessageVerb int

const (
	// NoMV represents no Message Verb
	NoMV MessageVerb = iota
)

// MessageInfoKey represents a key in the Info attribute of a Message.
type MessageInfoKey int

const (
	// LineIK represents an IRC line message info key
	LineIK MessageInfoKey = iota
)
