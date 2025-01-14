// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/tidwall/buntdb"

	"github.com/ergochat/ergo/irc/bunt"
	"github.com/ergochat/ergo/irc/datastore"
	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/utils"
	"github.com/ergochat/ergo/irc/webpush"
)

const (
	// produce a hardcoded version of the database schema
	// XXX instead of referencing, e.g., keyAccountExists, we should write in the string literal
	// (to ensure that no matter what code changes happen elsewhere, we're still producing a
	// db of the hardcoded version)
	importDBSchemaVersion = 24
)

type userImport struct {
	Name            string
	Hash            string
	Email           string
	RegisteredAt    int64 `json:"registeredAt"`
	Vhost           string
	AdditionalNicks []string `json:"additionalNicks"`
	Certfps         []string
}

type channelImport struct {
	Name         string
	Founder      string
	RegisteredAt int64 `json:"registeredAt"`
	Topic        string
	TopicSetBy   string `json:"topicSetBy"`
	TopicSetAt   int64  `json:"topicSetAt"`
	Amode        map[string]string
	Modes        string
	Key          string
	Limit        int
	Forward      string
}

type databaseImport struct {
	Version  int
	Source   string
	Users    map[string]userImport
	Channels map[string]channelImport
}

func convertAmodes(raw map[string]string, validCfUsernames utils.HashSet[string]) (result map[string]modes.Mode, err error) {
	result = make(map[string]modes.Mode)
	for accountName, mode := range raw {
		if len(mode) != 1 {
			return nil, fmt.Errorf("invalid mode %s for account %s", mode, accountName)
		}
		cfname, err := CasefoldName(accountName)
		if err != nil || !validCfUsernames.Has(cfname) {
			log.Printf("skipping invalid amode recipient %s\n", accountName)
		} else {
			result[cfname] = modes.Mode(mode[0])
		}
	}
	return
}

func doImportDBGeneric(config *Config, dbImport databaseImport, credsType CredentialsVersion, tx *buntdb.Tx) (err error) {
	requiredVersion := 1
	if dbImport.Version != requiredVersion {
		return fmt.Errorf("unsupported version of the db for import: version %d is required", requiredVersion)
	}

	tx.Set(keySchemaVersion, strconv.Itoa(importDBSchemaVersion), nil)
	tx.Set(keyCloakSecret, utils.GenerateSecretKey(), nil)
	vapidKeys, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		return err
	}
	vapidKeysJSON, err := json.Marshal(vapidKeys)
	if err != nil {
		return err
	}
	tx.Set(keyVAPIDKeys, string(vapidKeysJSON), nil)

	cfUsernames := make(utils.HashSet[string])
	skeletonToUsername := make(map[string]string)
	warnSkeletons := false

	for username, userInfo := range dbImport.Users {
		cfUsername, err := CasefoldName(username)
		skeleton, skErr := Skeleton(username)
		if err != nil || skErr != nil {
			log.Printf("invalid username %s: %v\n", username, err)
			continue
		}

		if existingSkelUser, ok := skeletonToUsername[skeleton]; ok {
			log.Printf("Users %s and %s have confusable nicknames; this may render one or both accounts unusable\n", username, existingSkelUser)
			warnSkeletons = true
		} else {
			skeletonToUsername[skeleton] = username
		}

		var certfps []string
		for _, certfp := range userInfo.Certfps {
			normalizedCertfp, err := utils.NormalizeCertfp(certfp)
			if err == nil {
				certfps = append(certfps, normalizedCertfp)
			} else {
				log.Printf("invalid certfp %s for %s\n", username, certfp)
			}
		}
		credentials := AccountCredentials{
			Version:        credsType,
			PassphraseHash: []byte(userInfo.Hash),
			Certfps:        certfps,
		}
		marshaledCredentials, err := json.Marshal(&credentials)
		if err != nil {
			log.Printf("invalid credentials for %s: %v\n", username, err)
			continue
		}
		tx.Set(fmt.Sprintf(keyAccountExists, cfUsername), "1", nil)
		tx.Set(fmt.Sprintf(keyAccountVerified, cfUsername), "1", nil)
		tx.Set(fmt.Sprintf(keyAccountName, cfUsername), userInfo.Name, nil)
		settings := AccountSettings{Email: userInfo.Email}
		settingsBytes, _ := json.Marshal(settings)
		tx.Set(fmt.Sprintf(keyAccountSettings, cfUsername), string(settingsBytes), nil)
		tx.Set(fmt.Sprintf(keyAccountCredentials, cfUsername), string(marshaledCredentials), nil)
		tx.Set(fmt.Sprintf(keyAccountRegTime, cfUsername), strconv.FormatInt(userInfo.RegisteredAt, 10), nil)
		if userInfo.Vhost != "" {
			vhinfo := VHostInfo{
				Enabled:       true,
				ApprovedVHost: userInfo.Vhost,
			}
			vhBytes, err := json.Marshal(vhinfo)
			if err == nil {
				tx.Set(fmt.Sprintf(keyAccountVHost, cfUsername), string(vhBytes), nil)
			} else {
				log.Printf("couldn't serialize vhost for %s: %v\n", username, err)
			}
		}
		if len(userInfo.AdditionalNicks) != 0 {
			tx.Set(fmt.Sprintf(keyAccountAdditionalNicks, cfUsername), marshalReservedNicks(userInfo.AdditionalNicks), nil)
		}
		for _, certfp := range certfps {
			tx.Set(fmt.Sprintf(keyCertToAccount, certfp), cfUsername, nil)
		}
		cfUsernames.Add(cfUsername)
	}

	// TODO fix this:
	for chname, chInfo := range dbImport.Channels {
		_, err := CasefoldChannel(chname)
		if err != nil {
			log.Printf("invalid channel name %s: %v", chname, err)
			continue
		}
		cffounder, err := CasefoldName(chInfo.Founder)
		if err != nil {
			log.Printf("invalid founder %s for channel %s: %v", chInfo.Founder, chname, err)
			continue
		}
		var regInfo RegisteredChannel
		regInfo.Name = chname
		regInfo.UUID = utils.GenerateUUIDv4()
		regInfo.Founder = cffounder
		regInfo.RegisteredAt = time.Unix(0, chInfo.RegisteredAt).UTC()
		if chInfo.Topic != "" {
			regInfo.Topic = chInfo.Topic
			regInfo.TopicSetBy = chInfo.TopicSetBy
			regInfo.TopicSetTime = time.Unix(0, chInfo.TopicSetAt).UTC()
		}

		if len(chInfo.Amode) != 0 {
			m, err := convertAmodes(chInfo.Amode, cfUsernames)
			if err == nil {
				regInfo.AccountToUMode = m
			} else {
				log.Printf("couldn't process amodes for %s: %v", chname, err)
			}
		}
		for _, mode := range chInfo.Modes {
			regInfo.Modes = append(regInfo.Modes, modes.Mode(mode))
		}
		regInfo.Key = chInfo.Key
		if chInfo.Limit > 0 {
			regInfo.UserLimit = chInfo.Limit
		}
		if chInfo.Forward != "" {
			if _, err := CasefoldChannel(chInfo.Forward); err == nil {
				regInfo.Forward = chInfo.Forward
			}
		}
		if j, err := json.Marshal(regInfo); err == nil {
			tx.Set(bunt.BuntKey(datastore.TableChannels, regInfo.UUID), string(j), nil)
		} else {
			log.Printf("couldn't serialize channel %s: %v", chname, err)
		}
	}

	if warnSkeletons {
		log.Printf("NOTE: you may be able to avoid confusability issues by changing the server casemapping setting to `ascii`\n")
		log.Printf("However, this will prevent the use of non-ASCII Unicode characters in nicknames\n")
	}

	return nil
}

func doImportDB(config *Config, dbImport databaseImport, tx *buntdb.Tx) (err error) {
	switch dbImport.Source {
	case "atheme":
		return doImportDBGeneric(config, dbImport, CredentialsAtheme, tx)
	case "anope":
		return doImportDBGeneric(config, dbImport, CredentialsAnope, tx)
	default:
		return fmt.Errorf("unsupported import source: %s", dbImport.Source)
	}
}

func ImportDB(config *Config, infile string) (err error) {
	data, err := os.ReadFile(infile)
	if err != nil {
		return
	}

	var dbImport databaseImport
	err = json.Unmarshal(data, &dbImport)
	if err != nil {
		return err
	}

	err = checkDBReadyForInit(config.Datastore.Path)
	if err != nil {
		return err
	}

	db, err := buntdb.Open(config.Datastore.Path)
	if err != nil {
		return err
	}

	performImport := func(tx *buntdb.Tx) (err error) {
		return doImportDB(config, dbImport, tx)
	}

	err = db.Update(performImport)
	db.Close()
	return
}
