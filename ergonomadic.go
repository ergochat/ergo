package main

import (
	"irc"
)

func main() {
	server := irc.NewServer()
	server.Listen(":6667")
}
