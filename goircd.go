package main
// http://tools.ietf.org/html/rfc1459

import (
	"irc"
)

func main() {
	server := irc.NewServer()
	server.Listen(":6697")
}
