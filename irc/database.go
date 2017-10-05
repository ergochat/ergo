// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/tidwall/buntdb"
)

const (
	// 'version' of the database schema
	keySchemaVersion = "db.version"
	// latest schema of the db
	latestDbSchema = "2"
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
		tx.Set(keySchemaVersion, "2", nil)
		return nil
	})

	if err != nil {
		log.Fatal("Could not save datastore:", err.Error())
	}
}

// OpenDatabase returns an existing database, performing a schema version check.
func OpenDatabase(path string) (*buntdb.DB, error) {
	// open data store
	db, err := buntdb.Open(path)
	if err != nil {
		return nil, err
	}

	// check db version
	err = db.View(func(tx *buntdb.Tx) error {
		version, _ := tx.Get(keySchemaVersion)
		if version != latestDbSchema {
			return fmt.Errorf("Database must be updated. Expected schema v%s, got v%s", latestDbSchema, version)
		}
		return nil
	})

	if err != nil {
		// close the db
		db.Close()
		return nil, err
	}

	return db, nil
}

// UpgradeDB upgrades the datastore to the latest schema.
func UpgradeDB(path string) {
	store, err := buntdb.Open(path)
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to open datastore: %s", err.Error()))
	}
	defer store.Close()

	err = store.Update(func(tx *buntdb.Tx) error {
		version, _ := tx.Get(keySchemaVersion)

		// == version 1 -> 2 ==
		// account key changes and account.verified key bugfix.
		if version == "1" {
			log.Println("Updating store v1 to v2")

			var keysToRemove []string
			newKeys := make(map[string]string)

			tx.AscendKeys("account *", func(key, value string) bool {
				keysToRemove = append(keysToRemove, key)
				splitkey := strings.Split(key, " ")

				// work around bug
				if splitkey[2] == "exists" {
					// manually create new verified key
					newVerifiedKey := fmt.Sprintf("%s.verified %s", splitkey[0], splitkey[1])
					newKeys[newVerifiedKey] = "1"
				} else if splitkey[1] == "%s" {
					return true
				}

				newKey := fmt.Sprintf("%s.%s %s", splitkey[0], splitkey[2], splitkey[1])
				newKeys[newKey] = value

				return true
			})

			for _, key := range keysToRemove {
				tx.Delete(key)
			}
			for key, value := range newKeys {
				tx.Set(key, value, nil)
			}

			tx.Set(keySchemaVersion, "2", nil)
		}

		return nil
	})
	if err != nil {
		log.Fatal("Could not update datastore:", err.Error())
	}

	return
}
