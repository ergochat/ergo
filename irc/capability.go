// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"github.com/oragono/oragono/irc/caps"
)

var (
	// SupportedCapabilities are the caps we advertise.
	// MaxLine, SASL and STS are set during server startup.
	SupportedCapabilities = caps.NewSet(caps.AccountTag, caps.AccountNotify, caps.AwayNotify, caps.CapNotify, caps.ChgHost, caps.EchoMessage, caps.ExtendedJoin, caps.InviteNotify, caps.Languages, caps.MessageTags, caps.MultiPrefix, caps.Rename, caps.Resume, caps.ServerTime, caps.UserhostInNames)

	// CapValues are the actual values we advertise to v3.2 clients.
	// actual values are set during server startup.
	CapValues = caps.NewValues()
)

// CapState shows whether we're negotiating caps, finished, etc for connection registration.
type CapState uint

const (
	// CapNone means CAP hasn't been negotiated at all.
	CapNone CapState = iota
	// CapNegotiating means CAP is being negotiated and registration should be paused.
	CapNegotiating CapState = iota
	// CapNegotiated means CAP negotiation has been successfully ended and reg should complete.
	CapNegotiated CapState = iota
)
