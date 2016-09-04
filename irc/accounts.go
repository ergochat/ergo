// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import "time"

// Account represents a user account.
type Account struct {
	// Name of the account.
	Name string
	// RegisteredAt represents the time that the account was registered.
	RegisteredAt time.Time
	// Clients that are currently logged into this account (useful for notifications).
	Clients []Client
}
