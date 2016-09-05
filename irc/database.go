// Copyright (c) 2012-2014 Jeremy Latt
// released under the MIT license

package irc

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"github.com/tidwall/buntdb"
)

const (
	// key for the primary salt used by the ircd
	keySalt = "crypto.salt"
)

func InitDB(buntpath string, path string) {
	// prepare kvstore db
	os.Remove(buntpath)
	store, err := buntdb.Open(buntpath)
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to open datastore: %s", err.Error()))
	}
	defer store.Close()

	err = store.Update(func(tx *buntdb.Tx) error {
		salt, err := NewSalt()
		encodedSalt := base64.StdEncoding.EncodeToString(salt)
		if err != nil {
			log.Fatal("Could not generate cryptographically-secure salt for the user:", err.Error())
		}
		tx.Set(keySalt, encodedSalt, nil)
		return nil
	})

	if err != nil {
		log.Fatal("Could not save bunt store:", err.Error())
	}

	// prepare SQLite db
	os.Remove(path)
	db := OpenDB(path)
	defer db.Close()
	_, err = db.Exec(`
        CREATE TABLE channel (
          name TEXT NOT NULL UNIQUE,
          flags TEXT DEFAULT '',
          key TEXT DEFAULT '',
          topic TEXT DEFAULT '',
          user_limit INTEGER DEFAULT 0,
          ban_list TEXT DEFAULT '',
          except_list TEXT DEFAULT '',
          invite_list TEXT DEFAULT '')`)
	if err != nil {
		log.Fatal("initdb error: ", err)
	}
}

func UpgradeDB(path string) {
	db := OpenDB(path)
	alter := `ALTER TABLE channel ADD COLUMN %s TEXT DEFAULT ''`
	cols := []string{"ban_list", "except_list", "invite_list"}
	for _, col := range cols {
		_, err := db.Exec(fmt.Sprintf(alter, col))
		if err != nil {
			log.Fatal("updatedb error: ", err)
		}
	}
}

func OpenDB(path string) *sql.DB {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		log.Fatal("open db error: ", err)
	}
	return db
}
