// Copyright (c) 2022 Shivaram Lingamneni
// released under the MIT license

package bunt

import (
	"fmt"
	"strings"
	"time"

	"github.com/tidwall/buntdb"

	"github.com/ergochat/ergo/irc/datastore"
	"github.com/ergochat/ergo/irc/logger"
	"github.com/ergochat/ergo/irc/utils"
)

// BuntKey yields a string key corresponding to a (table, UUID) pair.
// Ideally this would not be public, but some of the migration code
// needs it.
func BuntKey(table datastore.Table, uuid utils.UUID) string {
	return fmt.Sprintf("%x %s", table, uuid.String())
}

// buntdbDatastore implements datastore.Datastore using a buntdb.
type buntdbDatastore struct {
	db     *buntdb.DB
	logger *logger.Manager
}

// NewBuntdbDatastore returns a datastore.Datastore backed by buntdb.
func NewBuntdbDatastore(db *buntdb.DB, logger *logger.Manager) datastore.Datastore {
	return &buntdbDatastore{
		db:     db,
		logger: logger,
	}
}

func (b *buntdbDatastore) Backoff() time.Duration {
	return 0
}

func (b *buntdbDatastore) GetAll(table datastore.Table) (result []datastore.KV, err error) {
	tablePrefix := fmt.Sprintf("%x ", table)
	err = b.db.View(func(tx *buntdb.Tx) error {
		err := tx.AscendGreaterOrEqual("", tablePrefix, func(key, value string) bool {
			encUUID, ok := strings.CutPrefix(key, tablePrefix)
			if !ok {
				return false
			}
			uuid, err := utils.DecodeUUID(encUUID)
			if err == nil {
				result = append(result, datastore.KV{UUID: uuid, Value: []byte(value)})
			} else {
				b.logger.Error("datastore", "invalid uuid", key)
			}
			return true
		})
		return err
	})
	return
}

func (b *buntdbDatastore) Get(table datastore.Table, uuid utils.UUID) (value []byte, err error) {
	buntKey := BuntKey(table, uuid)
	var result string
	err = b.db.View(func(tx *buntdb.Tx) error {
		result, err = tx.Get(buntKey)
		return err
	})
	return []byte(result), err
}

func (b *buntdbDatastore) Set(table datastore.Table, uuid utils.UUID, value []byte, expiration time.Time) (err error) {
	buntKey := BuntKey(table, uuid)
	var setOptions *buntdb.SetOptions
	if !expiration.IsZero() {
		ttl := time.Until(expiration)
		if ttl > 0 {
			setOptions = &buntdb.SetOptions{Expires: true, TTL: ttl}
		} else {
			return nil // it already expired, i guess?
		}
	}
	strVal := string(value)

	err = b.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(buntKey, strVal, setOptions)
		return err
	})
	return
}

func (b *buntdbDatastore) Delete(table datastore.Table, key utils.UUID) (err error) {
	buntKey := BuntKey(table, key)
	err = b.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(buntKey)
		return err
	})
	// deleting a nonexistent key is not considered an error
	switch err {
	case buntdb.ErrNotFound:
		return nil
	default:
		return err
	}
}
