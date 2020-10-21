// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package irc

import (
	"testing"
)

func TestUserMaskSet(t *testing.T) {
	s := NewUserMaskSet()

	if s.Match("horse!~evan@tor-network.onion") {
		t.Errorf("empty set should not match anything")
	}

	s.Add("m:horse!*@*", "", "")
	if s.Match("horse!~evan@tor-network.onion") {
		t.Errorf("mute extbans should not Match(), only MatchMute()")
	}

	s.Add("*!~evan@*", "", "")
	if !s.Match("horse!~evan@tor-network.onion") {
		t.Errorf("expected Match() failed")
	}
	if s.Match("horse!~horse@tor-network.onion") {
		t.Errorf("unexpected Match() succeeded")
	}

	if !s.MatchMute("horse!~evan@tor-network.onion") {
		t.Errorf("expected MatchMute() failed")
	}
	if s.MatchMute("evan!~evan@tor-network.onion") {
		t.Errorf("unexpected MatchMute() succeeded")
	}
}
