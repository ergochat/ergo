package main

import (
	"flag"
	"fmt"
	"github.com/jlatt/ergonomadic/irc"
	"log"
	"os"
	"path/filepath"
)

func main() {
	conf := flag.String("conf", "ergonomadic.conf", "ergonomadic config file")
	initdb := flag.Bool("initdb", false, "initialize database")
	upgradedb := flag.Bool("upgradedb", false, "update database")
	passwd := flag.String("genpasswd", "", "bcrypt a password")
	flag.Parse()

	if *passwd != "" {
		encoded, err := irc.GenerateEncodedPassword(*passwd)
		if err != nil {
			log.Fatal("encoding error: ", err)
		}
		fmt.Println(encoded)
		return
	}

	config, err := irc.LoadConfig(*conf)
	if err != nil {
		log.Fatal("error loading config: ", err)
	}
	err = os.Chdir(filepath.Dir(*conf))
	if err != nil {
		log.Fatal("chdir error: ", err)
	}

	if *initdb {
		irc.InitDB(config.Server.Database)
		log.Println("database initialized: ", config.Server.Database)
		return
	}

	if *upgradedb {
		irc.UpgradeDB(config.Server.Database)
		log.Println("database upgraded: ", config.Server.Database)
		return
	}

	irc.Log.SetLevel(config.Server.Log)
	server := irc.NewServer(config)
	log.Println(irc.SEM_VER, "running")
	defer log.Println(irc.SEM_VER, "exiting")
	server.Run()
}
