package main

import (
	"fmt"
	"log"
	"syscall"

	"github.com/DanielOaks/oragono/irc"
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
		irc.InitDB(config.Server.Database)
		log.Println("database initialized: ", config.Server.Database)
	} else if arguments["upgradedb"].(bool) {
		irc.UpgradeDB(config.Server.Database)
		log.Println("database upgraded: ", config.Server.Database)
	} else if arguments["run"].(bool) {
		irc.Log.SetLevel(config.Server.Log)
		server := irc.NewServer(config)
		log.Println(irc.SEM_VER, "running")
		defer log.Println(irc.SEM_VER, "exiting")
		server.Run()
	}
}
