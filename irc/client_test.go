// Copyright (c) 2019 Shivaram Lingamneni
// released under the MIT license

package irc

import (
	"testing"

	"github.com/ergochat/ergo/irc/utils"
)

func TestGenerateBatchID(t *testing.T) {
	var session Session
	s := make(utils.HashSet[string])

	count := 100000
	for i := 0; i < count; i++ {
		s.Add(session.generateBatchID())
	}

	if len(s) != count {
		t.Error("duplicate batch ID detected")
	}
}

func BenchmarkGenerateBatchID(b *testing.B) {
	var session Session
	for i := 0; i < b.N; i++ {
		session.generateBatchID()
	}
}

func TestUserMasks(t *testing.T) {
	var um UserMaskSet

	if um.Match("horse_!user@tor-network.onion") {
		t.Error("bad match")
	}

	um.Add("_!*@*", "x", "x")
	if !um.Match("_!user@tor-network.onion") {
		t.Error("failure to match")
	}
	if um.Match("horse_!user@tor-network.onion") {
		t.Error("bad match")
	}

	um.Add("beer*!*@*", "x", "x")
	if !um.Match("beergarden!user@tor-network.onion") {
		t.Error("failure to match")
	}
	if um.Match("horse_!user@tor-network.onion") {
		t.Error("bad match")
	}

	um.Add("horse*!user@*", "x", "x")
	if !um.Match("horse_!user@tor-network.onion") {
		t.Error("failure to match")
	}
}

func TestWhoFields(t *testing.T) {
	var w whoxFields

	if w.Has('a') {
		t.Error("zero value of whoxFields must be empty")
	}
	w = w.Add('a')
	if !w.Has('a') {
		t.Error("failed to set and get")
	}
	if w.Has('A') {
		t.Error("false positive")
	}
	if w.Has('o') {
		t.Error("false positive")
	}
	w = w.Add('🐬')
	if w.Has('🐬') {
		t.Error("should not be able to set invalid who field")
	}
	w = w.Add('o')
	if !w.Has('o') {
		t.Error("failed to set and get")
	}
	w = w.Add('z')
	if !w.Has('z') {
		t.Error("failed to set and get")
	}
}
