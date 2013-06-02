package main

import (
	"flag"
	"irc"
)

func main() {
	flag.Parse()
	db := irc.NewDatabase()
	defer db.Close()
	irc.ExecSqlFile(db, flag.Arg(0)+".sql")
}
