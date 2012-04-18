package main

import (
	"flag"
	"irc"
)

func main() {
	name := flag.String("name", "localhost", "A name for the server")
	listen := flag.String("listen", ":6667", "interface to listen on")
    flag.Parse()
	irc.NewServer(*name).Listen(*listen)
}
