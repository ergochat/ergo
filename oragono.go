// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package main

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
	"syscall"
	"time"

	"net"

	"encoding/base64"

	"github.com/docopt/docopt-go"
	"github.com/oragono/oragono/irc"
	cloak "github.com/oragono/oragono/irc/cloaking"
	"github.com/oragono/oragono/irc/logger"
	"github.com/oragono/oragono/mkcerts"
	stackimpact "github.com/stackimpact/stackimpact-go"
	"golang.org/x/crypto/ssh/terminal"
)

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

	keyA, _ := base64.StdEncoding.DecodeString("idXACDbEhqRZsExn0jOTi4rtC6MrKBOcN4edxdSzTAA=")
	keyB, _ := base64.StdEncoding.DecodeString("qODtg8WEJ0YA6JRnryDDUEoSdJyrGgPFI6hPNnGHyIw=")
	keyC, _ := base64.StdEncoding.DecodeString("Oxqc6uDsyEO5vZcxHmtZ1zOLL8wwATeYA4KqJmkTJQo=")
	keyD, _ := base64.StdEncoding.DecodeString("vd2eimWWh3L9fukFwxZThJ9pKTf/I5UZ/k7o/3JHkMc=")

	conf := cloak.Config{
		Enabled:  true,
		NetName:  "Test",
		IPv4KeyA: keyA,
		IPv4KeyB: keyB,
		IPv4KeyC: keyC,
		IPv4KeyD: keyD,
	}
	ip := net.ParseIP("8.8.8.8")
	key, err := cloak.IPv4(ip, conf)
	fmt.Println(ip, key, err)
	ip = net.ParseIP("9.4.8.8")
	key, err = cloak.IPv4(ip, conf)
	fmt.Println(ip, key, err)
	ip = net.ParseIP("8.4.2.8")
	key, err = cloak.IPv4(ip, conf)
	fmt.Println(ip, key, err)
	ip = net.ParseIP("8.4.2.1")
	key, err = cloak.IPv4(ip, conf)
	fmt.Println(ip, key, err)

	arguments, _ := docopt.Parse(usage, nil, true, version, false)

	configfile := arguments["--conf"].(string)
	config, err := irc.LoadConfig(configfile)
	if err != nil {
		log.Fatal("Config file did not load successfully:", err.Error())
	}

	// assemble separate log configs
	var logConfigs []logger.Config
	for _, lConfig := range config.Logging {
		logConfigs = append(logConfigs, logger.Config{
			MethodStdout:  lConfig.MethodStdout,
			MethodStderr:  lConfig.MethodStderr,
			MethodFile:    lConfig.MethodFile,
			Filename:      lConfig.Filename,
			Level:         lConfig.Level,
			Types:         lConfig.Types,
			ExcludedTypes: lConfig.ExcludedTypes,
		})
	}

	logger, err := logger.NewManager(logConfigs...)
	if err != nil {
		log.Fatal("Logger did not load successfully:", err.Error())
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
			log.Fatal("encoding error:", err.Error())
		}
		fmt.Print("\n")
		fmt.Println(encoded)
	} else if arguments["initdb"].(bool) {
		irc.InitDB(config.Datastore.Path)
		if !arguments["--quiet"].(bool) {
			log.Println("database initialized: ", config.Datastore.Path)
		}
	} else if arguments["upgradedb"].(bool) {
		irc.UpgradeDB(config.Datastore.Path)
		if !arguments["--quiet"].(bool) {
			log.Println("database upgraded: ", config.Datastore.Path)
		}
	} else if arguments["mkcerts"].(bool) {
		if !arguments["--quiet"].(bool) {
			log.Println("making self-signed certificates")
		}

		for name, conf := range config.Server.TLSListeners {
			log.Printf(" making cert for %s listener\n", name)
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
		rand.Seed(time.Now().UTC().UnixNano())
		if !arguments["--quiet"].(bool) {
			logger.Info("startup", fmt.Sprintf("Oragono v%s starting", irc.SemVer))
		}

		// profiling
		if config.Debug.StackImpact.Enabled {
			if config.Debug.StackImpact.AgentKey == "" || config.Debug.StackImpact.AppName == "" {
				logger.Error("startup", "Could not start StackImpact - agent-key or app-name are undefined")
				return
			}

			agent := stackimpact.NewAgent()
			agent.Start(stackimpact.Options{AgentKey: config.Debug.StackImpact.AgentKey, AppName: config.Debug.StackImpact.AppName})
			defer agent.RecordPanic()

			logger.Info("startup", fmt.Sprintf("StackImpact profiling started as %s", config.Debug.StackImpact.AppName))
		}

		// warning if running a non-final version
		if strings.Contains(irc.SemVer, "unreleased") {
			logger.Warning("startup", "You are currently running an unreleased beta version of Oragono that may be unstable and could corrupt your database.\nIf you are running a production network, please download the latest build from https://oragono.io/downloads.html and run that instead.")
		}

		server, err := irc.NewServer(configfile, config, logger)
		if err != nil {
			logger.Error("startup", fmt.Sprintf("Could not load server: %s", err.Error()))
			return
		}
		if !arguments["--quiet"].(bool) {
			logger.Info("startup", "Server running")
			defer logger.Info("shutdown", fmt.Sprintf("Oragono v%s exiting", irc.SemVer))
		}
		server.Run()
	}
}
