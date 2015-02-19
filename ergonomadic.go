package main

import (
	"flag"
	"fmt"
	"github.com/edmund-huber/ergonomadic/irc"
	"log"
	"os"
	"path/filepath"
)

func usage() {
	fmt.Fprintln(os.Stderr, "ergonomadic <run|genpasswd|initdb|upgradedb> [options]")
	fmt.Fprintln(os.Stderr, "  run -conf <config>     -- run server")
	fmt.Fprintln(os.Stderr, "  initdb -conf <config>  -- initialize database")
	fmt.Fprintln(os.Stderr, "  upgrade -conf <config> -- upgrade database")
	fmt.Fprintln(os.Stderr, "  genpasswd <password>   -- bcrypt a password")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "software version:", irc.SEM_VER)
	flag.PrintDefaults()
}

func loadConfig(conf string) *irc.Config {
	config, err := irc.LoadConfig(conf)
	if err != nil {
		log.Fatalln("error loading config:", err)
	}

	err = os.Chdir(filepath.Dir(conf))
	if err != nil {
		log.Fatalln("chdir error:", err)
	}
	return config
}

func genPasswd() {
}

func main() {
	var conf string
	flag.Usage = usage

	runFlags := flag.NewFlagSet("run", flag.ExitOnError)
	runFlags.Usage = usage
	runFlags.StringVar(&conf, "conf", "ergonomadic.conf", "ergonomadic config file")

	flag.Parse()

	switch flag.Arg(0) {
	case "genpasswd":
		encoded, err := irc.GenerateEncodedPassword(flag.Arg(1))
		if err != nil {
			log.Fatalln("encoding error:", err)
		}
		fmt.Println(encoded)

	case "initdb":
		runFlags.Parse(flag.Args()[1:])
		config := loadConfig(conf)
		irc.InitDB(config.Server.Database)
		log.Println("database initialized: ", config.Server.Database)

	case "upgradedb":
		runFlags.Parse(flag.Args()[1:])
		config := loadConfig(conf)
		irc.UpgradeDB(config.Server.Database)
		log.Println("database upgraded: ", config.Server.Database)

	case "run":
		runFlags.Parse(flag.Args()[1:])
		config := loadConfig(conf)
		irc.Log.SetLevel(config.Server.Log)
		server := irc.NewServer(config)
		log.Println(irc.SEM_VER, "running")
		defer log.Println(irc.SEM_VER, "exiting")
		server.Run()

	default:
		usage()
	}
}
