// Copyright (c) 2019 Shivaram Lingamneni
// released under the MIT license

package irc

import (
	"fmt"
	"testing"
	"time"

	"github.com/ergochat/ergo/irc/caps"
	"github.com/ergochat/ergo/irc/languages"
	"github.com/ergochat/ergo/irc/utils"
)

func TestClientQuitLineLabeled(t *testing.T) {
	nuh := "foo!~user@127.0.0.1"
	now := time.Now().UTC()

	// #2402: a client-initiated QUIT must carry the labeled-response label
	var labeled Session
	labeled.capabilities.Enable(caps.LabeledResponse)
	labeled.quitLabel = "deadbeef"
	quitMsg := makeClientQuitLine(&labeled, nuh, "Quit: foo out", now)
	if _, value := quitMsg.GetTag(caps.LabelTagName); value != "deadbeef" {
		t.Errorf("expected QUIT line to carry label deadbeef, got %q", value)
	}

	// a QUIT with no pending label must not be tagged
	var unlabeled Session
	unlabeled.capabilities.Enable(caps.LabeledResponse)
	quitMsg = makeClientQuitLine(&unlabeled, nuh, "Quit: foo out", now)
	if quitMsg.HasTag(caps.LabelTagName) {
		t.Error("QUIT line without a pending label must not carry a label tag")
	}

	// a label must not be attached if the session lacks the labeled-response cap
	var noCap Session
	noCap.quitLabel = "deadbeef"
	quitMsg = makeClientQuitLine(&noCap, nuh, "Quit: foo out", now)
	if quitMsg.HasTag(caps.LabelTagName) {
		t.Error("QUIT line must not carry a label tag without the labeled-response cap")
	}
}

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

func BenchmarkNames(b *testing.B) {
	channelSize := 1024
	server := &Server{
		name: "ergo.test",
	}
	lm, err := languages.NewManager(false, "", "")
	if err != nil {
		b.Fatal(err)
	}
	server.config.Store(&Config{
		languageManager: lm,
	})
	for i := 0; i < b.N; i++ {
		channel := &Channel{
			name:           "#test",
			nameCasefolded: "#test",
			server:         server,
			members:        make(MemberSet),
		}
		for j := 0; j < channelSize; j++ {
			nick := fmt.Sprintf("client_%d", j)
			client := &Client{
				server:         server,
				nick:           nick,
				nickCasefolded: nick,
			}
			channel.members.Add(client)
			channel.regenerateMembersCache()
			session := &Session{
				client: client,
			}
			rb := NewResponseBuffer(session)
			channel.Names(client, rb)
			if len(rb.messages) < 2 {
				b.Fatalf("not enough messages: %d", len(rb.messages))
			}
			// to inspect the messages: line, _ := rb.messages[0].Line()
		}
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
