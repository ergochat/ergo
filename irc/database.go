// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/passwd"

	"github.com/tidwall/buntdb"
)

const (
	// 'version' of the database schema
	keySchemaVersion = "db.version"
	// latest schema of the db
	latestDbSchema = "3"
	// key for the primary salt used by the ircd
	keySalt = "crypto.salt"
)

type SchemaChanger func(*Config, *buntdb.Tx) error

type SchemaChange struct {
	InitialVersion string // the change will take this version
	TargetVersion  string // and transform it into this version
	Changer        SchemaChanger
}

// maps an initial version to a schema change capable of upgrading it
var schemaChanges map[string]SchemaChange

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
		salt, err := passwd.NewSalt()
		encodedSalt := base64.StdEncoding.EncodeToString(salt)
		if err != nil {
			log.Fatal("Could not generate cryptographically-secure salt for the user:", err.Error())
		}
		tx.Set(keySalt, encodedSalt, nil)

		// set schema version
		tx.Set(keySchemaVersion, latestDbSchema, nil)
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
func UpgradeDB(config *Config) {
	store, err := buntdb.Open(config.Datastore.Path)
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to open datastore: %s", err.Error()))
	}
	defer store.Close()

	var version string
	err = store.Update(func(tx *buntdb.Tx) error {
		for {
			version, _ = tx.Get(keySchemaVersion)
			change, schemaNeedsChange := schemaChanges[version]
			if !schemaNeedsChange {
				break
			}
			log.Println("attempting to update store from version " + version)
			err := change.Changer(config, tx)
			if err != nil {
				return err
			}
			_, _, err = tx.Set(keySchemaVersion, change.TargetVersion, nil)
			if err != nil {
				return err
			}
			log.Println("successfully updated store to version " + change.TargetVersion)
		}
		return nil
	})

	if err != nil {
		log.Fatal("Could not update datastore:", err.Error())
	}

	return
}

func schemaChangeV1toV2(config *Config, tx *buntdb.Tx) error {
	// == version 1 -> 2 ==
	// account key changes and account.verified key bugfix.

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

	return nil
}

// 1. channel founder names should be casefolded
// 2. founder should be explicitly granted the ChannelFounder user mode
// 3. explicitly initialize stored channel modes to the server default values
func schemaChangeV2ToV3(config *Config, tx *buntdb.Tx) error {
	var channels []string
	prefix := "channel.exists "
	tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
		if !strings.HasPrefix(key, prefix) {
			return false
		}
		chname := strings.TrimPrefix(key, prefix)
		channels = append(channels, chname)
		return true
	})

	// founder names should be casefolded
	// founder should be explicitly granted the ChannelFounder user mode
	for _, channel := range channels {
		founderKey := "channel.founder " + channel
		founder, _ := tx.Get(founderKey)
		if founder != "" {
			founder, err := CasefoldName(founder)
			if err == nil {
				tx.Set(founderKey, founder, nil)
				accountToUmode := map[string]modes.Mode{
					founder: modes.ChannelFounder,
				}
				atustr, _ := json.Marshal(accountToUmode)
				tx.Set("channel.accounttoumode "+channel, string(atustr), nil)
			}
		}
	}

	// explicitly store the channel modes
	defaultModes := ParseDefaultChannelModes(config)
	modeStrings := make([]string, len(defaultModes))
	for i, mode := range defaultModes {
		modeStrings[i] = string(mode)
	}
	defaultModeString := strings.Join(modeStrings, "")
	for _, channel := range channels {
		tx.Set("channel.modes "+channel, defaultModeString, nil)
	}

	return nil
}

func init() {
	allChanges := []SchemaChange{
		SchemaChange{
			InitialVersion: "1",
			TargetVersion:  "2",
			Changer:        schemaChangeV1toV2,
		},
		SchemaChange{
			InitialVersion: "2",
			TargetVersion:  "3",
			Changer:        schemaChangeV2ToV3,
		},
	}

	// build the index
	schemaChanges = make(map[string]SchemaChange)
	for _, change := range allChanges {
		schemaChanges[change.InitialVersion] = change
	}
}
