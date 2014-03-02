package irc

import (
	"database/sql"
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
          flags TEXT NOT NULL,
          key TEXT NOT NULL,
          topic TEXT NOT NULL,
          user_limit INTEGER DEFAULT 0)`)
	if err != nil {
		log.Fatal(err)
	}
}

func OpenDB(path string) *sql.DB {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		log.Fatal(err)
	}
	return db
}
