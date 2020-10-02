// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"strings"

	"github.com/tidwall/buntdb"

	"github.com/oragono/oragono/irc/utils"
)

type userImport struct {
	Name               string
	Hash               string
	Email              string
	RegisteredAt       int64 `json:"registeredAt"`
	Vhost              string
	AdditionalNicks    []string `json:"additionalNicks"`
	RegisteredChannels []string
}

type channelImport struct {
	Name         string
	Founder      string
	RegisteredAt int64 `json:"registeredAt"`
	Topic        string
	TopicSetBy   string `json:"topicSetBy"`
	TopicSetAt   int64  `json:"topicSetAt"`
	Amode        map[string]int
}

type databaseImport struct {
	Version  int
	Source   string
	Users    map[string]userImport
	Channels map[string]channelImport
}

func doImportAthemeDB(config *Config, dbImport databaseImport, tx *buntdb.Tx) (err error) {
	requiredVersion := 1
	if dbImport.Version != requiredVersion {
		return fmt.Errorf("unsupported version of the db for import: version %d is required", requiredVersion)
	}

	// produce a hardcoded version of the database schema
	// XXX instead of referencing, e.g., keyAccountExists, we should write in the string literal
	// (to ensure that no matter what code changes happen elsewhere, we're still producing a
	// version 14 db)
	tx.Set(keySchemaVersion, "14", nil)
	tx.Set(keyCloakSecret, utils.GenerateSecretKey(), nil)

	for username, userInfo := range dbImport.Users {
		cfUsername, err := CasefoldName(username)
		if err != nil {
			log.Printf("invalid username %s: %v", username, err)
			continue
		}
		credentials := AccountCredentials{
			Version:        CredentialsAtheme,
			PassphraseHash: []byte(userInfo.Hash),
		}
		marshaledCredentials, err := json.Marshal(&credentials)
		if err != nil {
			log.Printf("invalid credentials for %s: %v", username, err)
			continue
		}
		tx.Set(fmt.Sprintf(keyAccountExists, cfUsername), "1", nil)
		tx.Set(fmt.Sprintf(keyAccountVerified, cfUsername), "1", nil)
		tx.Set(fmt.Sprintf(keyAccountName, cfUsername), userInfo.Name, nil)
		tx.Set(fmt.Sprintf(keyAccountCallback, cfUsername), "mailto:"+userInfo.Email, nil)
		tx.Set(fmt.Sprintf(keyAccountCredentials, cfUsername), string(marshaledCredentials), nil)
		tx.Set(fmt.Sprintf(keyAccountRegTime, cfUsername), strconv.FormatInt(userInfo.RegisteredAt, 10), nil)
		if userInfo.Vhost != "" {
			tx.Set(fmt.Sprintf(keyAccountVHost, cfUsername), userInfo.Vhost, nil)
		}
		if len(userInfo.AdditionalNicks) != 0 {
			tx.Set(fmt.Sprintf(keyAccountAdditionalNicks, cfUsername), marshalReservedNicks(userInfo.AdditionalNicks), nil)
		}
		if len(userInfo.RegisteredChannels) != 0 {
			tx.Set(fmt.Sprintf(keyAccountChannels, cfUsername), strings.Join(userInfo.RegisteredChannels, ","), nil)
		}
	}

	for chname, chInfo := range dbImport.Channels {
		cfchname, err := CasefoldChannel(chname)
		if err != nil {
			log.Printf("invalid channel name %s: %v", chname, err)
			continue
		}
		tx.Set(fmt.Sprintf(keyChannelExists, cfchname), "1", nil)
		tx.Set(fmt.Sprintf(keyChannelName, cfchname), chname, nil)
		tx.Set(fmt.Sprintf(keyChannelRegTime, cfchname), strconv.FormatInt(chInfo.RegisteredAt, 10), nil)
		tx.Set(fmt.Sprintf(keyChannelFounder, cfchname), chInfo.Founder, nil)
		if chInfo.Topic != "" {
			tx.Set(fmt.Sprintf(keyChannelTopic, cfchname), chInfo.Topic, nil)
			tx.Set(fmt.Sprintf(keyChannelTopicSetTime, cfchname), strconv.FormatInt(chInfo.TopicSetAt, 10), nil)
			tx.Set(fmt.Sprintf(keyChannelTopicSetBy, cfchname), chInfo.TopicSetBy, nil)
		}
		if len(chInfo.Amode) != 0 {
			m, err := json.Marshal(chInfo.Amode)
			if err == nil {
				tx.Set(fmt.Sprintf(keyChannelAccountToUMode, cfchname), string(m), nil)
			} else {
				log.Printf("couldn't serialize amodes for %s: %v", chname, err)
			}
		}
	}

	return nil
}

func doImportDB(config *Config, dbImport databaseImport, tx *buntdb.Tx) (err error) {
	switch dbImport.Source {
	case "atheme":
		return doImportAthemeDB(config, dbImport, tx)
	default:
		return fmt.Errorf("only imports from atheme are currently supported")
	}
}

func ImportDB(config *Config, infile string) (err error) {
	data, err := ioutil.ReadFile(infile)
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

	return db.Update(performImport)
}
