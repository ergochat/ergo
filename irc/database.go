// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/utils"

	"github.com/tidwall/buntdb"
)

const (
	// 'version' of the database schema
	keySchemaVersion = "db.version"
	// latest schema of the db
	latestDbSchema = "3"
)

type SchemaChanger func(*Config, *buntdb.Tx) error

type SchemaChange struct {
	InitialVersion string // the change will take this version
	TargetVersion  string // and transform it into this version
	Changer        SchemaChanger
}

// maps an initial version to a schema change capable of upgrading it
var schemaChanges map[string]SchemaChange

type incompatibleSchemaError struct {
	currentVersion  string
	requiredVersion string
}

func IncompatibleSchemaError(currentVersion string) (result *incompatibleSchemaError) {
	return &incompatibleSchemaError{
		currentVersion:  currentVersion,
		requiredVersion: latestDbSchema,
	}
}

func (err *incompatibleSchemaError) Error() string {
	return fmt.Sprintf("Database requires update. Expected schema v%s, got v%s", err.requiredVersion, err.currentVersion)
}

// InitDB creates the database, implementing the `oragono initdb` command.
func InitDB(path string) {
	_, err := os.Stat(path)
	if err == nil {
		log.Fatal("Datastore already exists (delete it manually to continue): ", path)
	} else if !os.IsNotExist(err) {
		log.Fatal("Datastore path is inaccessible: ", err.Error())
	}

	err = initializeDB(path)
	if err != nil {
		log.Fatal("Could not save datastore: ", err.Error())
	}
}

// internal database initialization code
func initializeDB(path string) error {
	store, err := buntdb.Open(path)
	if err != nil {
		return err
	}
	defer store.Close()

	err = store.Update(func(tx *buntdb.Tx) error {
		// set schema version
		tx.Set(keySchemaVersion, latestDbSchema, nil)
		return nil
	})

	return err
}

// OpenDatabase returns an existing database, performing a schema version check.
func OpenDatabase(config *Config) (*buntdb.DB, error) {
	return openDatabaseInternal(config, config.Datastore.AutoUpgrade)
}

// open the database, giving it at most one chance to auto-upgrade the schema
func openDatabaseInternal(config *Config, allowAutoupgrade bool) (db *buntdb.DB, err error) {
	db, err = buntdb.Open(config.Datastore.Path)
	if err != nil {
		return
	}

	defer func() {
		if err != nil && db != nil {
			db.Close()
			db = nil
		}
	}()

	// read the current version string
	var version string
	err = db.View(func(tx *buntdb.Tx) error {
		version, err = tx.Get(keySchemaVersion)
		return err
	})
	if err != nil {
		return
	}

	if version == latestDbSchema {
		// success
		return
	}

	// XXX quiesce the DB so we can be sure it's safe to make a backup copy
	db.Close()
	db = nil
	if allowAutoupgrade {
		err = performAutoUpgrade(version, config)
		if err != nil {
			return
		}
		// successful autoupgrade, let's try this again:
		return openDatabaseInternal(config, false)
	} else {
		err = IncompatibleSchemaError(version)
		return
	}
}

func performAutoUpgrade(currentVersion string, config *Config) (err error) {
	path := config.Datastore.Path
	log.Printf("attempting to auto-upgrade schema from version %s to %s\n", currentVersion, latestDbSchema)
	timestamp := time.Now().UTC().Format("2006-01-02-15:04:05.000Z")
	backupPath := fmt.Sprintf("%s.v%s.%s.bak", path, currentVersion, timestamp)
	log.Printf("making a backup of current database at %s\n", backupPath)
	err = utils.CopyFile(path, backupPath)
	if err != nil {
		return err
	}

	err = UpgradeDB(config)
	if err != nil {
		// database upgrade is a single transaction, so we don't need to restore the backup;
		// we can just delete it
		os.Remove(backupPath)
	}
	return err
}

// UpgradeDB upgrades the datastore to the latest schema.
func UpgradeDB(config *Config) (err error) {
	store, err := buntdb.Open(config.Datastore.Path)
	if err != nil {
		return err
	}
	defer store.Close()

	var version string
	err = store.Update(func(tx *buntdb.Tx) error {
		for {
			version, _ = tx.Get(keySchemaVersion)
			change, schemaNeedsChange := schemaChanges[version]
			if !schemaNeedsChange {
				if version == latestDbSchema {
					// success!
					break
				}
				// unable to upgrade to the desired version, roll back
				return IncompatibleSchemaError(version)
			}
			log.Println("attempting to update schema from version " + version)
			err := change.Changer(config, tx)
			if err != nil {
				return err
			}
			_, _, err = tx.Set(keySchemaVersion, change.TargetVersion, nil)
			if err != nil {
				return err
			}
			log.Println("successfully updated schema to version " + change.TargetVersion)
		}
		return nil
	})

	if err != nil {
		log.Println("database upgrade failed and was rolled back")
	}
	return err
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
	defaultModes := config.Channels.defaultModes
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
		{
			InitialVersion: "1",
			TargetVersion:  "2",
			Changer:        schemaChangeV1toV2,
		},
		{
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
