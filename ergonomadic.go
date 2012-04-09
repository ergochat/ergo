package main
// http://tools.ietf.org/html/rfc2812

import (
	"irc"
)

func main() {
	server := irc.NewServer()
	server.Listen(":6667")
}
