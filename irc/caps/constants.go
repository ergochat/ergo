// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package caps

import "errors"

// Capability represents an optional feature that a client may request from the server.
type Capability uint

// actual capability definitions appear in defs.go

var (
	nameToCapability map[string]Capability

	NoSuchCap = errors.New("Unsupported capability name")
)

// Name returns the name of the given capability.
func (capability Capability) Name() string {
	return capabilityNames[capability]
}

func NameToCapability(name string) (result Capability, err error) {
	result, found := nameToCapability[name]
	if !found {
		err = NoSuchCap
	}
	return
}

// Version is used to select which max version of CAP the client supports.
type Version uint

const (
	// Cap301 refers to the base CAP spec.
	Cap301 Version = 301
	// Cap302 refers to the IRCv3.2 CAP spec.
	Cap302 Version = 302
)

// State shows whether we're negotiating caps, finished, etc for connection registration.
type State uint

const (
	// NoneState means CAP hasn't been negotiated at all.
	NoneState State = iota
	// NegotiatingState means CAP is being negotiated and registration should be paused.
	NegotiatingState State = iota
	// NegotiatedState means CAP negotiation has been successfully ended and reg should complete.
	NegotiatedState State = iota
)

const (
	// LabelTagName is the tag name used for the labeled-response spec.
	// https://ircv3.net/specs/extensions/labeled-response.html
	LabelTagName = "label"
	// More draft names associated with draft/multiline:
	MultilineBatchType = "draft/multiline"
	MultilineConcatTag = "draft/multiline-concat"
	// draft/relaymsg:
	RelaymsgTagName = "draft/relaymsg"
	// BOT mode: https://ircv3.net/specs/extensions/bot-mode
	BotTagName = "bot"
	// https://ircv3.net/specs/extensions/chathistory
	ChathistoryTargetsBatchType = "draft/chathistory-targets"
)

func init() {
	nameToCapability = make(map[string]Capability)
	for capab, name := range capabilityNames {
		nameToCapability[name] = Capability(capab)
	}
}
