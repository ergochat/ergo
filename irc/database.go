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
	"strconv"
	"strings"
	"time"

	"github.com/ergochat/ergo/irc/bunt"
	"github.com/ergochat/ergo/irc/datastore"
	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/utils"

	"github.com/tidwall/buntdb"
)

const (
	// TODO migrate metadata keys as well

	// 'version' of the database schema
	// latest schema of the db
	latestDbSchema = 23
)

var (
	schemaVersionUUID = utils.UUID{0, 255, 85, 13, 212, 10, 191, 121, 245, 152, 142, 89, 97, 141, 219, 87}    // AP9VDdQKv3n1mI5ZYY3bVw
	cloakSecretUUID   = utils.UUID{170, 214, 184, 208, 116, 181, 67, 75, 161, 23, 233, 16, 113, 251, 94, 229} // qta40HS1Q0uhF-kQcfte5Q

	keySchemaVersion = bunt.BuntKey(datastore.TableMetadata, schemaVersionUUID)
	keyCloakSecret   = bunt.BuntKey(datastore.TableMetadata, cloakSecretUUID)
)

type SchemaChanger func(*Config, *buntdb.Tx) error

type SchemaChange struct {
	InitialVersion int // the change will take this version
	TargetVersion  int // and transform it into this version
	Changer        SchemaChanger
}

func checkDBReadyForInit(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return fmt.Errorf("Datastore already exists (delete it manually to continue): %s", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("Datastore path %s is inaccessible: %w", path, err)
	}
	return nil
}

// InitDB creates the database, implementing the `oragono initdb` command.
func InitDB(path string) error {
	if err := checkDBReadyForInit(path); err != nil {
		return err
	}

	if err := initializeDB(path); err != nil {
		return fmt.Errorf("Could not save datastore: %w", err)
	}
	return nil
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
		tx.Set(keySchemaVersion, strconv.Itoa(latestDbSchema), nil)
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
	var version int
	err = db.View(func(tx *buntdb.Tx) (err error) {
		version, err = retrieveSchemaVersion(tx)
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

func retrieveSchemaVersion(tx *buntdb.Tx) (version int, err error) {
	if val, err := tx.Get(keySchemaVersion); err == nil {
		return strconv.Atoi(val)
	}
	// legacy key:
	if val, err := tx.Get("db.version"); err == nil {
		return strconv.Atoi(val)
	}
	return 0, buntdb.ErrNotFound
}

func performAutoUpgrade(currentVersion int, config *Config) (err error) {
	path := config.Datastore.Path
	log.Printf("attempting to auto-upgrade schema from version %d to %d\n", currentVersion, latestDbSchema)
	timestamp := time.Now().UTC().Format("2006-01-02-15.04.05.000Z")
	backupPath := fmt.Sprintf("%s.v%d.%s.bak", path, currentVersion, timestamp)
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

	var version int
	err = store.Update(func(tx *buntdb.Tx) error {
		for {
			if version == 0 {
				version, err = retrieveSchemaVersion(tx)
				if err != nil {
					return err
				}
			}
			if version == latestDbSchema {
				// success!
				break
			}
			change, ok := getSchemaChange(version)
			if !ok {
				// unable to upgrade to the desired version, roll back
				return &utils.IncompatibleSchemaError{CurrentVersion: version, RequiredVersion: latestDbSchema}
			}
			log.Printf("attempting to update schema from version %d\n", version)
			err := change.Changer(config, tx)
			if err != nil {
				return err
			}
			version = change.TargetVersion
			_, _, err = tx.Set(keySchemaVersion, strconv.Itoa(version), nil)
			if err != nil {
				return err
			}
			log.Printf("successfully updated schema to version %d\n", version)
		}
		return nil
	})

	if err != nil {
		log.Printf("database upgrade failed and was rolled back: %v\n", err)
	}
	return err
}

func LoadCloakSecret(dstore datastore.Datastore) (result string, err error) {
	val, err := dstore.Get(datastore.TableMetadata, cloakSecretUUID)
	if err != nil {
		return
	}
	return string(val), nil
}

func StoreCloakSecret(dstore datastore.Datastore, secret string) {
	// TODO error checking
	dstore.Set(datastore.TableMetadata, cloakSecretUUID, []byte(secret), time.Time{})
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

type accountCredsLegacyV13 struct {
	Version        CredentialsVersion
	PassphraseHash []byte
	Certfps        []string
}

// see #212 / #284. this packs the legacy salts into a single passphrase hash,
// allowing legacy passphrases to be verified using the new API `checkLegacyPassphrase`.
func schemaChangeV12ToV13(config *Config, tx *buntdb.Tx) error {
	salt, err := tx.Get("crypto.salt")
	if err != nil {
		return nil // no change required
	}
	tx.Delete("crypto.salt")
	rawSalt, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return nil // just throw away the creds at this point
	}
	prefix := "account.credentials "
	var accounts []string
	var credentials []accountCredsLegacyV13
	tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
		if !strings.HasPrefix(key, prefix) {
			return false
		}
		account := strings.TrimPrefix(key, prefix)

		var credsOld accountCredsLegacyV9
		err = json.Unmarshal([]byte(value), &credsOld)
		if err != nil {
			return true
		}
		// skip if these aren't legacy creds!
		if credsOld.Version != 0 {
			return true
		}

		var credsNew accountCredsLegacyV13
		credsNew.Version = 0 // mark hash for migration
		credsNew.Certfps = credsOld.Certfps
		credsNew.PassphraseHash = append(credsNew.PassphraseHash, rawSalt...)
		credsNew.PassphraseHash = append(credsNew.PassphraseHash, credsOld.PassphraseSalt...)
		credsNew.PassphraseHash = append(credsNew.PassphraseHash, credsOld.PassphraseHash...)

		accounts = append(accounts, account)
		credentials = append(credentials, credsNew)
		return true
	})

	for i, account := range accounts {
		bytesOut, err := json.Marshal(credentials[i])
		if err != nil {
			return err
		}
		_, _, err = tx.Set(prefix+account, string(bytesOut), nil)
		if err != nil {
			return err
		}
	}

	return nil
}

// channel registration time and topic set time at nanosecond resolution
func schemaChangeV13ToV14(config *Config, tx *buntdb.Tx) error {
	prefix := "channel.registered.time "
	var channels, times []string
	tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
		if !strings.HasPrefix(key, prefix) {
			return false
		}
		channel := strings.TrimPrefix(key, prefix)
		channels = append(channels, channel)
		times = append(times, value)
		return true
	})

	billion := int64(time.Second)
	for i, channel := range channels {
		regTime, err := strconv.ParseInt(times[i], 10, 64)
		if err != nil {
			log.Printf("corrupt registration time entry for %s: %v\n", channel, err)
			continue
		}
		regTime = regTime * billion
		tx.Set(prefix+channel, strconv.FormatInt(regTime, 10), nil)

		topicTimeKey := "channel.topic.settime " + channel
		topicSetAt, err := tx.Get(topicTimeKey)
		if err == nil {
			if setTime, err := strconv.ParseInt(topicSetAt, 10, 64); err == nil {
				tx.Set(topicTimeKey, strconv.FormatInt(setTime*billion, 10), nil)
			}
		}
	}
	return nil
}

// #1327: delete any invalid klines
func schemaChangeV14ToV15(config *Config, tx *buntdb.Tx) error {
	prefix := "bans.klinev2 "
	var keys []string
	tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
		if !strings.HasPrefix(key, prefix) {
			return false
		}
		if key != strings.TrimSpace(key) {
			keys = append(keys, key)
		}
		return true
	})
	// don't bother trying to fix these up
	for _, key := range keys {
		tx.Delete(key)
	}
	return nil
}

// #1330: delete any stale realname records
func schemaChangeV15ToV16(config *Config, tx *buntdb.Tx) error {
	prefix := "account.realname "
	verifiedPrefix := "account.verified "
	var keys []string
	tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
		if !strings.HasPrefix(key, prefix) {
			return false
		}
		acct := strings.TrimPrefix(key, prefix)
		verifiedKey := verifiedPrefix + acct
		_, verifiedErr := tx.Get(verifiedKey)
		if verifiedErr != nil {
			keys = append(keys, key)
		}
		return true
	})
	for _, key := range keys {
		tx.Delete(key)
	}
	return nil
}

// #1346: remove vhost request queue
func schemaChangeV16ToV17(config *Config, tx *buntdb.Tx) error {
	prefix := "vhostQueue "
	var keys []string
	tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
		if !strings.HasPrefix(key, prefix) {
			return false
		}
		keys = append(keys, key)
		return true
	})

	for _, key := range keys {
		tx.Delete(key)
	}
	return nil
}

// #1274: we used to suspend accounts by deleting their "verified" key,
// now we save some metadata under a new key
func schemaChangeV17ToV18(config *Config, tx *buntdb.Tx) error {
	now := time.Now().UTC()

	exists := "account.exists "
	suspended := "account.suspended "
	verif := "account.verified "
	verifCode := "account.verificationcode "

	var accounts []string

	tx.AscendGreaterOrEqual("", exists, func(key, value string) bool {
		if !strings.HasPrefix(key, exists) {
			return false
		}
		account := strings.TrimPrefix(key, exists)
		_, verifiedErr := tx.Get(verif + account)
		_, verifCodeErr := tx.Get(verifCode + account)
		if verifiedErr != nil && verifCodeErr != nil {
			// verified key not present, but there's no code either,
			// this is a suspension
			accounts = append(accounts, account)
		}
		return true
	})

	type accountSuspensionV18 struct {
		TimeCreated time.Time
		Duration    time.Duration
		OperName    string
		Reason      string
	}

	for _, account := range accounts {
		var sus accountSuspensionV18
		sus.TimeCreated = now
		sus.OperName = "*"
		sus.Reason = "[unknown]"
		susBytes, err := json.Marshal(sus)
		if err != nil {
			return err
		}
		tx.Set(suspended+account, string(susBytes), nil)
	}

	return nil
}

// #1345: persist the channel-user modes of always-on clients
func schemaChangeV18To19(config *Config, tx *buntdb.Tx) error {
	channelToAmodesCache := make(map[string]map[string]modes.Mode)
	joinedto := "account.joinedto "
	var accounts []string
	var channels [][]string
	tx.AscendGreaterOrEqual("", joinedto, func(key, value string) bool {
		if !strings.HasPrefix(key, joinedto) {
			return false
		}
		accounts = append(accounts, strings.TrimPrefix(key, joinedto))
		var ch []string
		if value != "" {
			ch = strings.Split(value, ",")
		}
		channels = append(channels, ch)
		return true
	})

	for i := 0; i < len(accounts); i++ {
		account := accounts[i]
		channels := channels[i]
		tx.Delete(joinedto + account)
		newValue := make(map[string]string, len(channels))
		for _, channel := range channels {
			chcfname, err := CasefoldChannel(channel)
			if err != nil {
				continue
			}
			// get amodes from the channelToAmodesCache, fill if necessary
			amodes, ok := channelToAmodesCache[chcfname]
			if !ok {
				amodeStr, _ := tx.Get("channel.accounttoumode " + chcfname)
				if amodeStr != "" {
					jErr := json.Unmarshal([]byte(amodeStr), &amodes)
					if jErr != nil {
						log.Printf("error retrieving amodes for %s: %v\n", channel, jErr)
						amodes = nil
					}
				}
				// setting/using the nil value here is ok
				channelToAmodesCache[chcfname] = amodes
			}
			if mode, ok := amodes[account]; ok {
				newValue[channel] = string(mode)
			} else {
				newValue[channel] = ""
			}
		}
		newValueBytes, jErr := json.Marshal(newValue)
		if jErr != nil {
			log.Printf("couldn't serialize new mode values for v19: %v\n", jErr)
			continue
		}
		tx.Set("account.channeltomodes "+account, string(newValueBytes), nil)
	}

	return nil
}

// #1490: start tracking join times for always-on clients
func schemaChangeV19To20(config *Config, tx *buntdb.Tx) error {
	type joinData struct {
		Modes    string
		JoinTime int64
	}

	var accounts []string
	var data []string

	now := time.Now().UnixNano()

	prefix := "account.channeltomodes "
	tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
		if !strings.HasPrefix(key, prefix) {
			return false
		}
		accounts = append(accounts, strings.TrimPrefix(key, prefix))
		data = append(data, value)
		return true
	})

	for i, account := range accounts {
		var existingMap map[string]string
		err := json.Unmarshal([]byte(data[i]), &existingMap)
		if err != nil {
			return err
		}
		newMap := make(map[string]joinData)
		for channel, modeStr := range existingMap {
			newMap[channel] = joinData{
				Modes:    modeStr,
				JoinTime: now,
			}
		}
		serialized, err := json.Marshal(newMap)
		if err != nil {
			return err
		}
		tx.Set(prefix+account, string(serialized), nil)
	}

	return nil
}

// #734: move the email address into the settings object,
// giving people a way to change it
func schemaChangeV20To21(config *Config, tx *buntdb.Tx) error {
	type accountSettingsv21 struct {
		AutoreplayLines  *int
		NickEnforcement  NickEnforcementMethod
		AllowBouncer     MulticlientAllowedSetting
		ReplayJoins      ReplayJoinsSetting
		AlwaysOn         PersistentStatus
		AutoreplayMissed bool
		DMHistory        HistoryStatus
		AutoAway         PersistentStatus
		Email            string
	}
	var accounts []string
	var emails []string
	callbackPrefix := "account.callback "
	tx.AscendGreaterOrEqual("", callbackPrefix, func(key, value string) bool {
		if !strings.HasPrefix(key, callbackPrefix) {
			return false
		}
		account := strings.TrimPrefix(key, callbackPrefix)
		if _, err := tx.Get("account.verified " + account); err != nil {
			return true
		}
		if strings.HasPrefix(value, "mailto:") {
			accounts = append(accounts, account)
			emails = append(emails, strings.TrimPrefix(value, "mailto:"))
		}
		return true
	})
	for i, account := range accounts {
		var settings accountSettingsv21
		email := emails[i]
		settingsKey := "account.settings " + account
		settingsStr, err := tx.Get(settingsKey)
		if err == nil && settingsStr != "" {
			json.Unmarshal([]byte(settingsStr), &settings)
		}
		settings.Email = email
		settingsBytes, err := json.Marshal(settings)
		if err != nil {
			log.Printf("couldn't marshal settings for %s: %v\n", account, err)
		} else {
			tx.Set(settingsKey, string(settingsBytes), nil)
		}
		tx.Delete(callbackPrefix + account)
	}
	return nil
}

// #1676: we used to have ReplayJoinsNever, now it's desupported
func schemaChangeV21To22(config *Config, tx *buntdb.Tx) error {
	type accountSettingsv22 struct {
		AutoreplayLines  *int
		NickEnforcement  NickEnforcementMethod
		AllowBouncer     MulticlientAllowedSetting
		ReplayJoins      ReplayJoinsSetting
		AlwaysOn         PersistentStatus
		AutoreplayMissed bool
		DMHistory        HistoryStatus
		AutoAway         PersistentStatus
		Email            string
	}

	var accounts []string
	var serializedSettings []string
	settingsPrefix := "account.settings "
	tx.AscendGreaterOrEqual("", settingsPrefix, func(key, value string) bool {
		if !strings.HasPrefix(key, settingsPrefix) {
			return false
		}
		if value == "" {
			return true
		}
		account := strings.TrimPrefix(key, settingsPrefix)
		if _, err := tx.Get("account.verified " + account); err != nil {
			return true
		}
		var settings accountSettingsv22
		err := json.Unmarshal([]byte(value), &settings)
		if err != nil {
			log.Printf("error (v21-22) processing settings for %s: %v\n", account, err)
			return true
		}
		// if necessary, change ReplayJoinsNever (2) to ReplayJoinsCommandsOnly (0)
		if settings.ReplayJoins == ReplayJoinsSetting(2) {
			settings.ReplayJoins = ReplayJoinsSetting(0)
			if b, err := json.Marshal(settings); err == nil {
				accounts = append(accounts, account)
				serializedSettings = append(serializedSettings, string(b))
			} else {
				log.Printf("error (v21-22) processing settings for %s: %v\n", account, err)
			}
		}
		return true
	})

	for i, account := range accounts {
		tx.Set(settingsPrefix+account, serializedSettings[i], nil)
	}
	return nil
}

// first phase of document-oriented database refactor: channels
func schemaChangeV22ToV23(config *Config, tx *buntdb.Tx) error {
	keyChannelExists := "channel.exists "
	var channelNames []string
	tx.AscendGreaterOrEqual("", keyChannelExists, func(key, value string) bool {
		if !strings.HasPrefix(key, keyChannelExists) {
			return false
		}
		channelNames = append(channelNames, strings.TrimPrefix(key, keyChannelExists))
		return true
	})
	for _, channelName := range channelNames {
		channel, err := loadLegacyChannel(tx, channelName)
		if err != nil {
			log.Printf("error loading legacy channel %s: %v", channelName, err)
			continue
		}
		channel.UUID = utils.GenerateUUIDv4()
		newKey := bunt.BuntKey(datastore.TableChannels, channel.UUID)
		j, err := json.Marshal(channel)
		if err != nil {
			log.Printf("error marshaling channel %s: %v", channelName, err)
			continue
		}
		tx.Set(newKey, string(j), nil)
		deleteLegacyChannel(tx, channelName)
	}

	// purges
	keyChannelPurged := "channel.purged "
	var purgeKeys []string
	var channelPurges []ChannelPurgeRecord
	tx.AscendGreaterOrEqual("", keyChannelPurged, func(key, value string) bool {
		if !strings.HasPrefix(key, keyChannelPurged) {
			return false
		}
		purgeKeys = append(purgeKeys, key)
		cfname := strings.TrimPrefix(key, keyChannelPurged)
		var record ChannelPurgeRecord
		err := json.Unmarshal([]byte(value), &record)
		if err != nil {
			log.Printf("error unmarshaling channel purge for %s: %v", cfname, err)
			return true
		}
		record.NameCasefolded = cfname
		record.UUID = utils.GenerateUUIDv4()
		channelPurges = append(channelPurges, record)
		return true
	})
	for _, record := range channelPurges {
		newKey := bunt.BuntKey(datastore.TableChannelPurges, record.UUID)
		j, err := json.Marshal(record)
		if err != nil {
			log.Printf("error marshaling channel purge %s: %v", record.NameCasefolded, err)
			continue
		}
		tx.Set(newKey, string(j), nil)
	}
	for _, purgeKey := range purgeKeys {
		tx.Delete(purgeKey)
	}

	// clean up denormalized account-to-channels mapping
	keyAccountChannels := "account.channels "
	var accountToChannels []string
	tx.AscendGreaterOrEqual("", keyAccountChannels, func(key, value string) bool {
		if !strings.HasPrefix(key, keyAccountChannels) {
			return false
		}
		accountToChannels = append(accountToChannels, key)
		return true
	})
	for _, key := range accountToChannels {
		tx.Delete(key)
	}

	// migrate cloak secret
	val, _ := tx.Get("crypto.cloak_secret")
	tx.Set(keyCloakSecret, val, nil)

	// bump the legacy version key to mark the database as downgrade-incompatible
	tx.Set("db.version", "23", nil)

	return nil
}

func getSchemaChange(initialVersion int) (result SchemaChange, ok bool) {
	for _, change := range allChanges {
		if initialVersion == change.InitialVersion {
			return change, true
		}
	}
	return
}

var allChanges = []SchemaChange{
	{
		InitialVersion: 1,
		TargetVersion:  2,
		Changer:        schemaChangeV1toV2,
	},
	{
		InitialVersion: 2,
		TargetVersion:  3,
		Changer:        schemaChangeV2ToV3,
	},
	{
		InitialVersion: 3,
		TargetVersion:  4,
		Changer:        schemaChangeV3ToV4,
	},
	{
		InitialVersion: 4,
		TargetVersion:  5,
		Changer:        schemaChangeV4ToV5,
	},
	{
		InitialVersion: 5,
		TargetVersion:  6,
		Changer:        schemaChangeV5ToV6,
	},
	{
		InitialVersion: 6,
		TargetVersion:  7,
		Changer:        schemaChangeV6ToV7,
	},
	{
		InitialVersion: 7,
		TargetVersion:  8,
		Changer:        schemaChangeV7ToV8,
	},
	{
		InitialVersion: 8,
		TargetVersion:  9,
		Changer:        schemaChangeV8ToV9,
	},
	{
		InitialVersion: 9,
		TargetVersion:  10,
		Changer:        schemaChangeV9ToV10,
	},
	{
		InitialVersion: 10,
		TargetVersion:  11,
		Changer:        schemaChangeV10ToV11,
	},
	{
		InitialVersion: 11,
		TargetVersion:  12,
		Changer:        schemaChangeV11ToV12,
	},
	{
		InitialVersion: 12,
		TargetVersion:  13,
		Changer:        schemaChangeV12ToV13,
	},
	{
		InitialVersion: 13,
		TargetVersion:  14,
		Changer:        schemaChangeV13ToV14,
	},
	{
		InitialVersion: 14,
		TargetVersion:  15,
		Changer:        schemaChangeV14ToV15,
	},
	{
		InitialVersion: 15,
		TargetVersion:  16,
		Changer:        schemaChangeV15ToV16,
	},
	{
		InitialVersion: 16,
		TargetVersion:  17,
		Changer:        schemaChangeV16ToV17,
	},
	{
		InitialVersion: 17,
		TargetVersion:  18,
		Changer:        schemaChangeV17ToV18,
	},
	{
		InitialVersion: 18,
		TargetVersion:  19,
		Changer:        schemaChangeV18To19,
	},
	{
		InitialVersion: 19,
		TargetVersion:  20,
		Changer:        schemaChangeV19To20,
	},
	{
		InitialVersion: 20,
		TargetVersion:  21,
		Changer:        schemaChangeV20To21,
	},
	{
		InitialVersion: 21,
		TargetVersion:  22,
		Changer:        schemaChangeV21To22,
	},
	{
		InitialVersion: 22,
		TargetVersion:  23,
		Changer:        schemaChangeV22ToV23,
	},
}
