// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
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
	latestDbSchema = "12"

	keyCloakSecret = "crypto.cloak_secret"
)

type SchemaChanger func(*Config, *buntdb.Tx) error

type SchemaChange struct {
	InitialVersion string // the change will take this version
	TargetVersion  string // and transform it into this version
	Changer        SchemaChanger
}

// maps an initial version to a schema change capable of upgrading it
var schemaChanges map[string]SchemaChange

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
		tx.Set(keyCloakSecret, utils.GenerateSecretKey(), nil)
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
		err = &utils.IncompatibleSchemaError{CurrentVersion: version, RequiredVersion: latestDbSchema}
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
	// #715: test that the database exists
	_, err = os.Stat(config.Datastore.Path)
	if err != nil {
		return err
	}

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
				return &utils.IncompatibleSchemaError{CurrentVersion: version, RequiredVersion: latestDbSchema}
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
		log.Printf("database upgrade failed and was rolled back: %v\n", err)
	}
	return err
}

func LoadCloakSecret(db *buntdb.DB) (result string) {
	db.View(func(tx *buntdb.Tx) error {
		result, _ = tx.Get(keyCloakSecret)
		return nil
	})
	return
}

func StoreCloakSecret(db *buntdb.DB, secret string) {
	db.Update(func(tx *buntdb.Tx) error {
		tx.Set(keyCloakSecret, secret, nil)
		return nil
	})
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

// 1. ban info format changed (from `legacyBanInfo` below to `IPBanInfo`)
// 2. dlines against individual IPs are normalized into dlines against the appropriate /128 network
func schemaChangeV3ToV4(config *Config, tx *buntdb.Tx) error {
	type ipRestrictTime struct {
		Duration time.Duration
		Expires  time.Time
	}
	type legacyBanInfo struct {
		Reason     string          `json:"reason"`
		OperReason string          `json:"oper_reason"`
		OperName   string          `json:"oper_name"`
		Time       *ipRestrictTime `json:"time"`
	}

	now := time.Now()
	legacyToNewInfo := func(old legacyBanInfo) (new_ IPBanInfo) {
		new_.Reason = old.Reason
		new_.OperReason = old.OperReason
		new_.OperName = old.OperName

		if old.Time == nil {
			new_.TimeCreated = now
			new_.Duration = 0
		} else {
			new_.TimeCreated = old.Time.Expires.Add(-1 * old.Time.Duration)
			new_.Duration = old.Time.Duration
		}
		return
	}

	var keysToDelete []string

	prefix := "bans.dline "
	dlines := make(map[string]IPBanInfo)
	tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
		if !strings.HasPrefix(key, prefix) {
			return false
		}
		keysToDelete = append(keysToDelete, key)

		var lbinfo legacyBanInfo
		id := strings.TrimPrefix(key, prefix)
		err := json.Unmarshal([]byte(value), &lbinfo)
		if err != nil {
			log.Printf("error unmarshaling legacy dline: %v\n", err)
			return true
		}
		// legacy keys can be either an IP or a CIDR
		hostNet, err := utils.NormalizedNetFromString(id)
		if err != nil {
			log.Printf("error unmarshaling legacy dline network: %v\n", err)
			return true
		}
		dlines[utils.NetToNormalizedString(hostNet)] = legacyToNewInfo(lbinfo)

		return true
	})

	setOptions := func(info IPBanInfo) *buntdb.SetOptions {
		if info.Duration == 0 {
			return nil
		}
		ttl := info.TimeCreated.Add(info.Duration).Sub(now)
		return &buntdb.SetOptions{Expires: true, TTL: ttl}
	}

	// store the new dlines
	for id, info := range dlines {
		b, err := json.Marshal(info)
		if err != nil {
			log.Printf("error marshaling migrated dline: %v\n", err)
			continue
		}
		tx.Set(fmt.Sprintf("bans.dlinev2 %s", id), string(b), setOptions(info))
	}

	// same operations against klines
	prefix = "bans.kline "
	klines := make(map[string]IPBanInfo)
	tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
		if !strings.HasPrefix(key, prefix) {
			return false
		}
		keysToDelete = append(keysToDelete, key)
		mask := strings.TrimPrefix(key, prefix)
		var lbinfo legacyBanInfo
		err := json.Unmarshal([]byte(value), &lbinfo)
		if err != nil {
			log.Printf("error unmarshaling legacy kline: %v\n", err)
			return true
		}
		klines[mask] = legacyToNewInfo(lbinfo)
		return true
	})

	for mask, info := range klines {
		b, err := json.Marshal(info)
		if err != nil {
			log.Printf("error marshaling migrated kline: %v\n", err)
			continue
		}
		tx.Set(fmt.Sprintf("bans.klinev2 %s", mask), string(b), setOptions(info))
	}

	// clean up all the old entries
	for _, key := range keysToDelete {
		tx.Delete(key)
	}

	return nil
}

// create new key tracking channels that belong to an account
func schemaChangeV4ToV5(config *Config, tx *buntdb.Tx) error {
	founderToChannels := make(map[string][]string)
	prefix := "channel.founder "
	tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
		if !strings.HasPrefix(key, prefix) {
			return false
		}
		channel := strings.TrimPrefix(key, prefix)
		founderToChannels[value] = append(founderToChannels[value], channel)
		return true
	})

	for founder, channels := range founderToChannels {
		tx.Set(fmt.Sprintf("account.channels %s", founder), strings.Join(channels, ","), nil)
	}
	return nil
}

// custom nick enforcement was a separate db key, now it's part of settings
func schemaChangeV5ToV6(config *Config, tx *buntdb.Tx) error {
	accountToEnforcement := make(map[string]NickEnforcementMethod)
	prefix := "account.customenforcement "
	tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
		if !strings.HasPrefix(key, prefix) {
			return false
		}
		account := strings.TrimPrefix(key, prefix)
		method, err := nickReservationFromString(value)
		if err == nil {
			accountToEnforcement[account] = method
		} else {
			log.Printf("skipping corrupt custom enforcement value for %s\n", account)
		}
		return true
	})

	for account, method := range accountToEnforcement {
		var settings AccountSettings
		settings.NickEnforcement = method
		text, err := json.Marshal(settings)
		if err != nil {
			return err
		}
		tx.Delete(prefix + account)
		tx.Set(fmt.Sprintf("account.settings %s", account), string(text), nil)
	}
	return nil
}

type maskInfoV7 struct {
	TimeCreated     time.Time
	CreatorNickmask string
	CreatorAccount  string
}

func schemaChangeV6ToV7(config *Config, tx *buntdb.Tx) error {
	now := time.Now().UTC()
	var channels []string
	prefix := "channel.exists "
	tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
		if !strings.HasPrefix(key, prefix) {
			return false
		}
		channels = append(channels, strings.TrimPrefix(key, prefix))
		return true
	})

	converter := func(key string) {
		oldRawValue, err := tx.Get(key)
		if err != nil {
			return
		}
		var masks []string
		err = json.Unmarshal([]byte(oldRawValue), &masks)
		if err != nil {
			return
		}
		newCookedValue := make(map[string]maskInfoV7)
		for _, mask := range masks {
			normalizedMask, err := CanonicalizeMaskWildcard(mask)
			if err != nil {
				continue
			}
			newCookedValue[normalizedMask] = maskInfoV7{
				TimeCreated:     now,
				CreatorNickmask: "*",
				CreatorAccount:  "*",
			}
		}
		newRawValue, err := json.Marshal(newCookedValue)
		if err != nil {
			return
		}
		tx.Set(key, string(newRawValue), nil)
	}

	prefixes := []string{
		"channel.banlist %s",
		"channel.exceptlist %s",
		"channel.invitelist %s",
	}
	for _, channel := range channels {
		for _, prefix := range prefixes {
			converter(fmt.Sprintf(prefix, channel))
		}
	}
	return nil
}

type accountSettingsLegacyV7 struct {
	AutoreplayLines *int
	NickEnforcement NickEnforcementMethod
	AllowBouncer    MulticlientAllowedSetting
	AutoreplayJoins bool
}

type accountSettingsLegacyV8 struct {
	AutoreplayLines *int
	NickEnforcement NickEnforcementMethod
	AllowBouncer    MulticlientAllowedSetting
	ReplayJoins     ReplayJoinsSetting
}

// #616: change autoreplay-joins to replay-joins
func schemaChangeV7ToV8(config *Config, tx *buntdb.Tx) error {
	prefix := "account.settings "
	var accounts, blobs []string
	tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
		var legacy accountSettingsLegacyV7
		var current accountSettingsLegacyV8
		if !strings.HasPrefix(key, prefix) {
			return false
		}
		account := strings.TrimPrefix(key, prefix)
		err := json.Unmarshal([]byte(value), &legacy)
		if err != nil {
			log.Printf("corrupt record for %s: %v\n", account, err)
			return true
		}
		current.AutoreplayLines = legacy.AutoreplayLines
		current.NickEnforcement = legacy.NickEnforcement
		current.AllowBouncer = legacy.AllowBouncer
		if legacy.AutoreplayJoins {
			current.ReplayJoins = ReplayJoinsAlways
		} else {
			current.ReplayJoins = ReplayJoinsCommandsOnly
		}
		blob, err := json.Marshal(current)
		if err != nil {
			log.Printf("could not marshal record for %s: %v\n", account, err)
			return true
		}
		accounts = append(accounts, account)
		blobs = append(blobs, string(blob))
		return true
	})
	for i, account := range accounts {
		tx.Set(prefix+account, blobs[i], nil)
	}
	return nil
}

type accountCredsLegacyV8 struct {
	Version        uint
	PassphraseSalt []byte // legacy field, not used by v1 and later
	PassphraseHash []byte
	Certificate    string
}

type accountCredsLegacyV9 struct {
	Version        uint
	PassphraseSalt []byte // legacy field, not used by v1 and later
	PassphraseHash []byte
	Certfps        []string
}

// #530: support multiple client certificate fingerprints
func schemaChangeV8ToV9(config *Config, tx *buntdb.Tx) error {
	prefix := "account.credentials "
	var accounts, blobs []string
	tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
		var legacy accountCredsLegacyV8
		var current accountCredsLegacyV9
		if !strings.HasPrefix(key, prefix) {
			return false
		}
		account := strings.TrimPrefix(key, prefix)
		err := json.Unmarshal([]byte(value), &legacy)
		if err != nil {
			log.Printf("corrupt record for %s: %v\n", account, err)
			return true
		}
		current.Version = legacy.Version
		current.PassphraseSalt = legacy.PassphraseSalt // ugh can't get rid of this
		current.PassphraseHash = legacy.PassphraseHash
		if legacy.Certificate != "" {
			current.Certfps = []string{legacy.Certificate}
		}
		blob, err := json.Marshal(current)
		if err != nil {
			log.Printf("could not marshal record for %s: %v\n", account, err)
			return true
		}
		accounts = append(accounts, account)
		blobs = append(blobs, string(blob))
		return true
	})
	for i, account := range accounts {
		tx.Set(prefix+account, blobs[i], nil)
	}
	return nil
}

// #836: account registration time at nanosecond resolution
// (mostly to simplify testing)
func schemaChangeV9ToV10(config *Config, tx *buntdb.Tx) error {
	prefix := "account.registered.time "
	var accounts, times []string
	tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
		if !strings.HasPrefix(key, prefix) {
			return false
		}
		account := strings.TrimPrefix(key, prefix)
		accounts = append(accounts, account)
		times = append(times, value)
		return true
	})
	for i, account := range accounts {
		time, err := strconv.ParseInt(times[i], 10, 64)
		if err != nil {
			log.Printf("corrupt registration time entry for %s: %v\n", account, err)
			continue
		}
		time = time * 1000000000
		tx.Set(prefix+account, strconv.FormatInt(time, 10), nil)
	}
	return nil
}

// #952: move the cloak secret into the database,
// generate a new one if necessary
func schemaChangeV10ToV11(config *Config, tx *buntdb.Tx) error {
	cloakSecret := config.Server.Cloaks.LegacySecretValue
	if cloakSecret == "" || cloakSecret == "siaELnk6Kaeo65K3RCrwJjlWaZ-Bt3WuZ2L8MXLbNb4" {
		cloakSecret = utils.GenerateSecretKey()
	}
	_, _, err := tx.Set(keyCloakSecret, cloakSecret, nil)
	return err
}

// #1027: NickEnforcementTimeout (2) was removed,
// NickEnforcementStrict was 3 and is now 2
func schemaChangeV11ToV12(config *Config, tx *buntdb.Tx) error {
	prefix := "account.settings "
	var accounts, rawSettings []string
	tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
		if !strings.HasPrefix(key, prefix) {
			return false
		}
		account := strings.TrimPrefix(key, prefix)
		accounts = append(accounts, account)
		rawSettings = append(rawSettings, value)
		return true
	})

	for i, account := range accounts {
		var settings AccountSettings
		err := json.Unmarshal([]byte(rawSettings[i]), &settings)
		if err != nil {
			log.Printf("corrupt account settings entry for %s: %v\n", account, err)
			continue
		}
		// upgrade NickEnforcementTimeout (which was 2) to NickEnforcementStrict (currently 2),
		// fix up the old value of NickEnforcementStrict (3) to the current value (2)
		if int(settings.NickEnforcement) == 3 {
			settings.NickEnforcement = NickEnforcementMethod(2)
			text, err := json.Marshal(settings)
			if err != nil {
				return err
			}
			tx.Set(prefix+account, string(text), nil)
		}
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
		{
			InitialVersion: "3",
			TargetVersion:  "4",
			Changer:        schemaChangeV3ToV4,
		},
		{
			InitialVersion: "4",
			TargetVersion:  "5",
			Changer:        schemaChangeV4ToV5,
		},
		{
			InitialVersion: "5",
			TargetVersion:  "6",
			Changer:        schemaChangeV5ToV6,
		},
		{
			InitialVersion: "6",
			TargetVersion:  "7",
			Changer:        schemaChangeV6ToV7,
		},
		{
			InitialVersion: "7",
			TargetVersion:  "8",
			Changer:        schemaChangeV7ToV8,
		},
		{
			InitialVersion: "8",
			TargetVersion:  "9",
			Changer:        schemaChangeV8ToV9,
		},
		{
			InitialVersion: "9",
			TargetVersion:  "10",
			Changer:        schemaChangeV9ToV10,
		},
		{
			InitialVersion: "10",
			TargetVersion:  "11",
			Changer:        schemaChangeV10ToV11,
		},
		{
			InitialVersion: "11",
			TargetVersion:  "12",
			Changer:        schemaChangeV11ToV12,
		},
	}

	// build the index
	schemaChanges = make(map[string]SchemaChange)
	for _, change := range allChanges {
		schemaChanges[change.InitialVersion] = change
	}
}
