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

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/docopt/docopt-go"
	"github.com/ergochat/ergo/irc"
	"github.com/ergochat/ergo/irc/logger"
	"github.com/ergochat/ergo/irc/mkcerts"
)

// set via linker flags, either by make or by goreleaser:
var commit = ""  // git hash
var version = "" // tagged version

// get a password from stdin from the user
func getPasswordFromTerminal() string {
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal("Error reading password:", err.Error())
	}
	return string(bytePassword)
}

func fileDoesNotExist(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return true
	}
	return false
}

// implements the `ergo mkcerts` command
func doMkcerts(configFile string, quiet bool) {
	config, err := irc.LoadRawConfig(configFile)
	if err != nil {
		log.Fatal(err)
	}
	if !quiet {
		log.Println("making self-signed certificates")
	}

	certToKey := make(map[string]string)
	for name, conf := range config.Server.Listeners {
		if conf.TLS.Cert == "" {
			continue
		}
		existingKey, ok := certToKey[conf.TLS.Cert]
		if ok {
			if existingKey == conf.TLS.Key {
				continue
			} else {
				log.Fatal("Conflicting TLS key files for ", conf.TLS.Cert)
			}
		}
		if !quiet {
			log.Printf(" making cert for %s listener\n", name)
		}
		host := config.Server.Name
		cert, key := conf.TLS.Cert, conf.TLS.Key
		if !(fileDoesNotExist(cert) && fileDoesNotExist(key)) {
			log.Fatalf("Preexisting TLS cert and/or key files: %s %s", cert, key)
		}
		err := mkcerts.CreateCert("Ergo", host, cert, key)
		if err == nil {
			if !quiet {
				log.Printf("  Certificate created at %s : %s\n", cert, key)
			}
			certToKey[cert] = key
		} else {
			log.Fatal("  Could not create certificate:", err.Error())
		}
	}
}

func main() {
	irc.SetVersionString(version, commit)
	usage := `ergo.
Usage:
	ergo initdb [--conf <filename>] [--quiet]
	ergo upgradedb [--conf <filename>] [--quiet]
	ergo importdb <database.json> [--conf <filename>] [--quiet]
	ergo genpasswd [--conf <filename>] [--quiet]
	ergo mkcerts [--conf <filename>] [--quiet]
	ergo run [--conf <filename>] [--quiet] [--smoke]
	ergo -h | --help
	ergo --version
Options:
	--conf <filename>  Configuration file to use [default: ircd.yaml].
	--quiet            Don't show startup/shutdown lines.
	-h --help          Show this screen.
	--version          Show version.`

	arguments, _ := docopt.ParseArgs(usage, nil, irc.Ver)

	// don't require a config file for genpasswd
	if arguments["genpasswd"].(bool) {
		var password string
		if term.IsTerminal(int(syscall.Stdin)) {
			fmt.Print("Enter Password: ")
			password = getPasswordFromTerminal()
			fmt.Print("\n")
			fmt.Print("Reenter Password: ")
			confirm := getPasswordFromTerminal()
			fmt.Print("\n")
			if confirm != password {
				log.Fatal("passwords do not match")
			}
		} else {
			reader := bufio.NewReader(os.Stdin)
			text, _ := reader.ReadString('\n')
			password = strings.TrimSpace(text)
		}
		if err := irc.ValidatePassphrase(password); err != nil {
			log.Printf("WARNING: this password contains characters that may cause problems with your IRC client software.\n")
			log.Printf("We strongly recommend choosing a different password.\n")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			log.Fatal("encoding error:", err.Error())
		}
		fmt.Println(string(hash))
		return
	} else if arguments["mkcerts"].(bool) {
		doMkcerts(arguments["--conf"].(string), arguments["--quiet"].(bool))
		return
	}

	configfile := arguments["--conf"].(string)
	config, err := irc.LoadConfig(configfile)
	if err != nil {
		_, isCertError := err.(*irc.CertKeyError)
		if !(isCertError && arguments["mkcerts"].(bool)) {
			log.Fatal("Config file did not load successfully: ", err.Error())
		}
	}

	logman, err := logger.NewManager(config.Logging)
	if err != nil {
		log.Fatal("Logger did not load successfully:", err.Error())
	}

	if arguments["initdb"].(bool) {
		err = irc.InitDB(config.Datastore.Path)
		if err != nil {
			log.Fatal("Error while initializing db:", err.Error())
		}
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
	} else if arguments["importdb"].(bool) {
		err = irc.ImportDB(config, arguments["<database.json>"].(string))
		if err != nil {
			log.Fatal("Error while importing db:", err.Error())
		}
	} else if arguments["run"].(bool) {
		if !arguments["--quiet"].(bool) {
			logman.Info("server", fmt.Sprintf("%s starting", irc.Ver))
		}

		// warning if running a non-final version
		if strings.Contains(irc.Ver, "unreleased") {
			logman.Warning("server", "You are currently running an unreleased beta version of Ergo that may be unstable and could corrupt your database.\nIf you are running a production network, please download the latest build from https://ergo.chat/downloads.html and run that instead.")
		}

		server, err := irc.NewServer(config, logman)
		if err != nil {
			logman.Error("server", fmt.Sprintf("Could not load server: %s", err.Error()))
			os.Exit(1)
		}
		if !arguments["--smoke"].(bool) {
			server.Run()
		}
	}
}
