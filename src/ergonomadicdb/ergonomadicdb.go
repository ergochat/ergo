package main

import (
	"flag"
	"irc"
)

func main() {
	flag.Parse()
	irc.NewDatabase().ExecSqlFile(flag.Arg(0) + ".sql").Close()
}
