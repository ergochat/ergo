// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"

	"github.com/tidwall/buntdb"
)

// AccountRegistration manages the registration of accounts.
type AccountRegistration struct {
	Enabled                    bool
	EnabledCallbacks           []string
	EnabledCredentialTypes     []string
	AllowMultiplePerConnection bool
}

// AccountCredentials stores the various methods for verifying accounts.
type AccountCredentials struct {
	PassphraseSalt []byte
	PassphraseHash []byte
	Certificate    string // fingerprint
}

// NewAccountRegistration returns a new AccountRegistration, configured correctly.
func NewAccountRegistration(config AccountRegistrationConfig) (accountReg AccountRegistration) {
	if config.Enabled {
		accountReg.Enabled = true
		accountReg.AllowMultiplePerConnection = config.AllowMultiplePerConnection
		for _, name := range config.EnabledCallbacks {
			// we store "none" as "*" internally
			if name == "none" {
				name = "*"
			}
			accountReg.EnabledCallbacks = append(accountReg.EnabledCallbacks, name)
		}
		// no need to make this configurable, right now at least
		accountReg.EnabledCredentialTypes = []string{
			"passphrase",
			"certfp",
		}
	}
	return accountReg
}

// removeFailedAccRegisterData removes the data created by ACC REGISTER if the account creation fails early.
func removeFailedAccRegisterData(store *buntdb.DB, account string) {
	// error is ignored here, we can't do much about it anyways
	store.Update(func(tx *buntdb.Tx) error {
		tx.Delete(fmt.Sprintf(keyAccountExists, account))
		tx.Delete(fmt.Sprintf(keyAccountRegTime, account))
		tx.Delete(fmt.Sprintf(keyAccountCredentials, account))

		return nil
	})
}
