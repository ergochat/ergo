package irc

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"os"
)

func InitDB(path string) {
	os.Remove(path)
	db := OpenDB(path)
	defer db.Close()
	_, err := db.Exec(`
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
