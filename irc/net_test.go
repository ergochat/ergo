package irc

import "testing"

// hostnames from https://github.com/DanielOaks/irc-parser-tests
var (
	goodHostnames = []string{
		"irc.example.com",
		"i.coolguy.net",
		"irc-srv.net.uk",
		"iRC.CooLguY.NeT",
		"gsf.ds342.co.uk",
		"324.net.uk",
		"xn--bcher-kva.ch",
	}

	badHostnames = []string{
		"-lol-.net.uk",
		"-lol.net.uk",
		"_irc._sctp.lol.net.uk",
		"irc",
		"com",
		"",
	}
)

func TestIsHostname(t *testing.T) {
	for _, name := range goodHostnames {
		if !IsHostname(name) {
			t.Error(
				"Expected to pass, but could not validate hostname",
				name,
			)
		}
	}

	for _, name := range badHostnames {
		if IsHostname(name) {
			t.Error(
				"Expected to fail, but successfully validated hostname",
				name,
			)
		}
	}
}
