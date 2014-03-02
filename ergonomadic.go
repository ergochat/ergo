package main

import (
	"flag"
	"fmt"
	"github.com/jlatt/ergonomadic/irc"
	"log"
)

func main() {
	conf := flag.String("conf", "ergonomadic.json", "ergonomadic config file")
	initdb := flag.Bool("initdb", false, "initialize database")
	passwd := flag.String("genpasswd", "", "bcrypt a password")
	flag.Parse()

	if *passwd != "" {
		encoded, err := irc.GenerateEncodedPassword(*passwd)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(encoded)
		return
	}

	config, err := irc.LoadConfig(*conf)
	if err != nil {
		log.Fatal(err)
	}

	if *initdb {
		irc.InitDB(config.Database())
		log.Println("database initialized: " + config.Database())
		return
	}

	// TODO move to data structures
	irc.DEBUG_NET = config.Debug["net"]
	irc.DEBUG_CLIENT = config.Debug["client"]
	irc.DEBUG_CHANNEL = config.Debug["channel"]
	irc.DEBUG_SERVER = config.Debug["server"]

	irc.NewServer(config).Run()
}
