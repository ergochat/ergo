// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import "time"

var (
	NoAccount = ClientAccount{
		Name: "*", // * is used until actual account name is set
	}
)

// ClientAccount represents a user account.
type ClientAccount struct {
	// Name of the account.
	Name string
	// RegisteredAt represents the time that the account was registered.
	RegisteredAt time.Time
	// Clients that are currently logged into this account (useful for notifications).
	Clients []*Client
}
