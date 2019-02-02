// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/docopt/docopt-go"
	"github.com/oragono/oragono/irc"
	"github.com/oragono/oragono/irc/logger"
	"github.com/oragono/oragono/irc/mkcerts"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
)

var commit = ""

// get a password from stdin from the user
func getPassword() string {
	fd := int(os.Stdin.Fd())
	if terminal.IsTerminal(fd) {
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal("Error reading password:", err.Error())
		}
		return string(bytePassword)
	}
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	return text
}

func main() {
	version := irc.SemVer
	usage := `oragono.
Usage:
	oragono initdb [--conf <filename>] [--quiet]
	oragono upgradedb [--conf <filename>] [--quiet]
	oragono genpasswd [--conf <filename>] [--quiet]
	oragono mkcerts [--conf <filename>] [--quiet]
	oragono run [--conf <filename>] [--quiet]
	oragono -h | --help
	oragono --version
Options:
	--conf <filename>  Configuration file to use [default: ircd.yaml].
	--quiet            Don't show startup/shutdown lines.
	-h --help          Show this screen.
	--version          Show version.`

	arguments, _ := docopt.ParseArgs(usage, nil, version)

	// don't require a config file for genpasswd
	if arguments["genpasswd"].(bool) {
		var password string
		fd := int(os.Stdin.Fd())
		if terminal.IsTerminal(fd) {
			fmt.Print("Enter Password: ")
			password = getPassword()
			fmt.Print("\n")
			fmt.Print("Reenter Password: ")
			confirm := getPassword()
			fmt.Print("\n")
			if confirm != password {
				log.Fatal("passwords do not match")
			}
		} else {
			password = getPassword()
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			log.Fatal("encoding error:", err.Error())
		}
		fmt.Print(string(hash))
		if terminal.IsTerminal(fd) {
			fmt.Println()
		}
		return
	}

	configfile := arguments["--conf"].(string)
	config, err := irc.LoadConfig(configfile)
	if err != nil {
		log.Fatal("Config file did not load successfully: ", err.Error())
	}

	logman, err := logger.NewManager(config.Logging)
	if err != nil {
		log.Fatal("Logger did not load successfully:", err.Error())
	}

	if arguments["initdb"].(bool) {
		irc.InitDB(config.Datastore.Path)
		if !arguments["--quiet"].(bool) {
			log.Println("database initialized: ", config.Datastore.Path)
		}
	} else if arguments["upgradedb"].(bool) {
		err = irc.UpgradeDB(config)
		if err != nil {
			log.Fatal("Error while upgrading db:", err.Error())
		}
		if !arguments["--quiet"].(bool) {
			log.Println("database upgraded: ", config.Datastore.Path)
		}
	} else if arguments["mkcerts"].(bool) {
		if !arguments["--quiet"].(bool) {
			log.Println("making self-signed certificates")
		}

		for name, conf := range config.Server.TLSListeners {
			if !arguments["--quiet"].(bool) {
				log.Printf(" making cert for %s listener\n", name)
			}
			host := config.Server.Name
			err := mkcerts.CreateCert("Oragono", host, conf.Cert, conf.Key)
			if err == nil {
				if !arguments["--quiet"].(bool) {
					log.Printf("  Certificate created at %s : %s\n", conf.Cert, conf.Key)
				}
			} else {
				log.Fatal("  Could not create certificate:", err.Error())
			}
		}
	} else if arguments["run"].(bool) {
		if !arguments["--quiet"].(bool) {
			logman.Info("startup", fmt.Sprintf("Oragono v%s starting", irc.SemVer))
			if commit == "" {
				logman.Debug("startup", fmt.Sprintf("Could not get current commit"))
			} else {
				logman.Info("startup", fmt.Sprintf("Running commit %s", commit))
			}
		}

		// set current git commit
		irc.Commit = commit
		if commit != "" {
			irc.Ver = fmt.Sprintf("%s-%s", irc.Ver, commit)
		}

		// warning if running a non-final version
		if strings.Contains(irc.SemVer, "unreleased") {
			logman.Warning("startup", "You are currently running an unreleased beta version of Oragono that may be unstable and could corrupt your database.\nIf you are running a production network, please download the latest build from https://oragono.io/downloads.html and run that instead.")
		}

		server, err := irc.NewServer(config, logman)
		if err != nil {
			logman.Error("startup", fmt.Sprintf("Could not load server: %s", err.Error()))
			return
		}
		if !arguments["--quiet"].(bool) {
			logman.Info("startup", "Server running")
			defer logman.Info("shutdown", fmt.Sprintf("Oragono v%s exiting", irc.SemVer))
		}
		server.Run()
	}
}
