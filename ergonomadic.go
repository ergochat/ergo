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
	"path/filepath"
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
	os.Remove(config.Server.Database)

	db, err := sql.Open("sqlite3", config.Server.Database)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`
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
	err = os.Chdir(filepath.Dir(*conf))
	if err != nil {
		log.Fatal(err)
	}

	if *initdb {
		initDB(config)
		return
	}

	// TODO move to data structures
	irc.DEBUG_NET = config.Debug.Net
	irc.DEBUG_CLIENT = config.Debug.Client
	irc.DEBUG_CHANNEL = config.Debug.Channel
	irc.DEBUG_SERVER = config.Debug.Server

	irc.NewServer(config).Run()
}
