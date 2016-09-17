// Copyright (c) 2012-2014 Jeremy Latt
// released under the MIT license

package irc

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/tidwall/buntdb"
)

const (
	// 'version' of the database schema
	keySchemaVersion = "db.version"
	// key for the primary salt used by the ircd
	keySalt = "crypto.salt"
)

// InitDB creates the database.
func InitDB(path string) {
	// prepare kvstore db
	//TODO(dan): fail if already exists instead? don't want to overwrite good data
	os.Remove(path)
	store, err := buntdb.Open(path)
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to open datastore: %s", err.Error()))
	}
	defer store.Close()

	err = store.Update(func(tx *buntdb.Tx) error {
		// set base db salt
		salt, err := NewSalt()
		encodedSalt := base64.StdEncoding.EncodeToString(salt)
		if err != nil {
			log.Fatal("Could not generate cryptographically-secure salt for the user:", err.Error())
		}
		tx.Set(keySalt, encodedSalt, nil)

		// set schema version
		tx.Set(keySchemaVersion, "1", nil)
		return nil
	})

	if err != nil {
		log.Fatal("Could not save bunt store:", err.Error())
	}
}

// UpgradeDB upgrades the datastore to the latest schema.
func UpgradeDB(path string) {
	return
}
