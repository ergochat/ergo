package main

import (
	"flag"
	"github.com/jlatt/ergonomadic/irc"
)

func main() {
	name := flag.String("name", "ergonomadic", "A name for the server")
	listen := flag.String("listen", ":6667", "interface to listen on")
	flag.BoolVar(&irc.DEBUG_NET, "dnet", false, "debug net")
	flag.BoolVar(&irc.DEBUG_CLIENT, "dclient", false, "debug client")
	flag.BoolVar(&irc.DEBUG_CHANNEL, "dchannel", false, "debug channel")
	flag.BoolVar(&irc.DEBUG_SERVER, "dserver", false, "debug server")
	flag.Parse()
	irc.NewServer(*name).Listen(*listen)
}
