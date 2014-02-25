package main

import (
	"code.google.com/p/go.crypto/bcrypt"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/jlatt/ergonomadic/irc"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"os"
)

func genPasswd(passwd string) {
	crypted, err := bcrypt.GenerateFromPassword([]byte(passwd), bcrypt.MinCost)
	if err != nil {
		log.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(crypted)
	fmt.Println(encoded)
}

func initDB(config *irc.Config) {
	os.Remove(config.Database())

	db, err := sql.Open("sqlite3", config.Database())
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`
        CREATE TABLE channel (
          name TEXT NOT NULL UNIQUE,
          flags TEXT,
          key TEXT,
          topic TEXT,
          user_limit INTEGER)`)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	conf := flag.String("conf", "ergonomadic.json", "ergonomadic config file")
	initdb := flag.Bool("initdb", false, "initialize database")
	passwd := flag.String("genpasswd", "", "bcrypt a password")
	flag.Parse()

	if *passwd != "" {
		genPasswd(*passwd)
		return
	}

	config, err := irc.LoadConfig(*conf)
	if err != nil {
		log.Fatal(err)
	}

	if *initdb {
		initDB(config)
		return
	}

	// TODO move to data structures
	irc.DEBUG_NET = config.Debug["net"]
	irc.DEBUG_CLIENT = config.Debug["client"]
	irc.DEBUG_CHANNEL = config.Debug["channel"]
	irc.DEBUG_SERVER = config.Debug["server"]

	irc.NewServer(config).Run()
}
