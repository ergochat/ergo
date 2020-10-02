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

// set via linker flags, either by make or by goreleaser:
var commit = ""  // git hash
var version = "" // tagged version

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
	return strings.TrimSpace(text)
}

func fileDoesNotExist(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return true
	}
	return false
}

// implements the `oragono mkcerts` command
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
		err := mkcerts.CreateCert("Oragono", host, cert, key)
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
	usage := `oragono.
Usage:
	oragono initdb [--conf <filename>] [--quiet]
	oragono upgradedb [--conf <filename>] [--quiet]
	oragono importdb <database.json> [--conf <filename>] [--quiet]
	oragono genpasswd [--conf <filename>] [--quiet]
	oragono mkcerts [--conf <filename>] [--quiet]
	oragono run [--conf <filename>] [--quiet] [--smoke]
	oragono -h | --help
	oragono --version
Options:
	--conf <filename>  Configuration file to use [default: ircd.yaml].
	--quiet            Don't show startup/shutdown lines.
	-h --help          Show this screen.
	--version          Show version.`

	arguments, _ := docopt.ParseArgs(usage, nil, irc.Ver)

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
			logman.Warning("server", "You are currently running an unreleased beta version of Oragono that may be unstable and could corrupt your database.\nIf you are running a production network, please download the latest build from https://oragono.io/downloads.html and run that instead.")
		}

		server, err := irc.NewServer(config, logman)
		if err != nil {
			logman.Error("server", fmt.Sprintf("Could not load server: %s", err.Error()))
			os.Exit(1)
		}
		if !arguments["--quiet"].(bool) {
			logman.Info("server", "Server running")
			defer logman.Info("server", fmt.Sprintf("Oragono v%s exiting", irc.SemVer))
		}
		if !arguments["--smoke"].(bool) {
			server.Run()
		}
	}
}
