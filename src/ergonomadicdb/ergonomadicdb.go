package main

import (
	"flag"
	"irc"
)

var (
	actions = map[string]func(*irc.Database){
		"init": func(db *irc.Database) {
			db.InitTables()
		},
		"drop": func(db *irc.Database) {
			db.DropTables()
		},
	}
)

func main() {
	flag.Parse()
	actions[flag.Arg(0)](irc.NewDatabase())
}
