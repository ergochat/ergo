// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package main

import (
	"fmt"
	"log"

	"github.com/DanielOaks/oragono/irc"
	"github.com/DanielOaks/oragono/mkcerts"
	"github.com/DanielOaks/oragono/web"
	"github.com/docopt/docopt-go"
)

func main() {
	version := irc.SemVer
	usage := `oragono-web.
Usage:
	oragono-web mkcerts [--conf <filename>] [--quiet]
	oragono-web run [--conf <filename>] [--quiet]
	oragono-web -h | --help
	oragono-web --version
Options:
	--conf <filename>  Configuration file to use [default: web.yaml].
	--quiet            Don't show startup/shutdown lines.
	-h --help          Show this screen.
	--version          Show version.`

	arguments, _ := docopt.Parse(usage, nil, true, version, false)

	configfile := arguments["--conf"].(string)
	config, err := web.LoadConfig(configfile)
	if err != nil {
		log.Fatal("Config file did not load successfully:", err.Error())
	}

	if arguments["mkcerts"].(bool) {
		if !arguments["--quiet"].(bool) {
			log.Println("making self-signed certificates")
		}

		for name, conf := range config.TLSListenersConf {
			log.Printf(" making cert for %s listener\n", name)
			host := config.Host
			err := mkcerts.CreateCert("Oragono web interface", host, conf.Cert, conf.Key)
			if err == nil {
				if !arguments["--quiet"].(bool) {
					log.Printf("  Certificate created at %s : %s\n", conf.Cert, conf.Key)
				}
			} else {
				log.Fatal("  Could not create certificate:", err.Error())
			}
		}
	} else if arguments["run"].(bool) {
		irc.Log.SetLevel(config.Log)
		server := web.NewServer(config)
		if server == nil {
			log.Println("Could not load server")
			return
		}
		if !arguments["--quiet"].(bool) {
			log.Println(fmt.Sprintf("Oragono web interface v%s running", irc.SemVer))
			defer log.Println(irc.SemVer, "exiting")
		}
		server.Run()
	}
}
