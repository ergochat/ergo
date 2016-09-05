// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package main

import (
	"fmt"
	"log"
	"syscall"

	"github.com/DanielOaks/oragono/irc"
	"github.com/DanielOaks/oragono/mkcerts"
	"github.com/docopt/docopt-go"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	version := irc.SEM_VER
	usage := `oragono.
Usage:
	oragono initdb [--conf <filename>]
	oragono upgradedb [--conf <filename>]
	oragono genpasswd [--conf <filename>]
	oragono mkcerts [--conf <filename>]
	oragono run [--conf <filename>]
	oragono -h | --help
	oragono --version
Options:
	--conf <filename>  Configuration file to use [default: ircd.yaml].
	-h --help          Show this screen.
	--version          Show version.`

	arguments, _ := docopt.Parse(usage, nil, true, version, false)

	configfile := arguments["--conf"].(string)
	config, err := irc.LoadConfig(configfile)
	if err != nil {
		log.Fatal("Config file did not load successfully:", err.Error())
	}

	if arguments["genpasswd"].(bool) {
		fmt.Print("Enter Password: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal("Error reading password:", err.Error())
		}
		password := string(bytePassword)
		encoded, err := irc.GenerateEncodedPassword(password)
		if err != nil {
			log.Fatalln("encoding error:", err)
		}
		fmt.Print("\n")
		fmt.Println(encoded)
	} else if arguments["initdb"].(bool) {
		irc.InitDB(config.Datastore.Path, config.Datastore.SQLitePath)
		log.Println("databases initialized: ", config.Datastore.Path, config.Datastore.SQLitePath)
	} else if arguments["upgradedb"].(bool) {
		irc.UpgradeDB(config.Datastore.SQLitePath)
		log.Println("database upgraded: ", config.Datastore.SQLitePath)
	} else if arguments["mkcerts"].(bool) {
		log.Println("making self-signed certificates")

		for name, conf := range config.Server.TLSListeners {
			log.Printf(" making cert for %s listener\n", name)
			host := config.Server.Name
			err := mkcerts.CreateCert("Oragono", host, conf.Cert, conf.Key)
			if err == nil {
				log.Printf("  Certificate created at %s : %s\n", conf.Cert, conf.Key)
			} else {
				log.Fatal("  Could not create certificate:", err.Error())
			}
		}
	} else if arguments["run"].(bool) {
		irc.Log.SetLevel(config.Server.Log)
		server := irc.NewServer(config)
		log.Println(irc.SEM_VER, "running")
		defer log.Println(irc.SEM_VER, "exiting")
		server.Run()
	}
}
