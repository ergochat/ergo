package webpush

import (
	"strings"
	"testing"
	"time"

	"github.com/ergochat/irc-go/ircmsg"

	"github.com/ergochat/ergo/irc/utils"
)

func TestBuildPushLine(t *testing.T) {
	now, err := time.Parse(utils.IRCv3TimestampFormat, "2025-01-12T00:55:44.403Z")
	if err != nil {
		panic(err)
	}

	line, err := MakePushLine(now, "*", "ergo.test", "MARKREAD", "#ergo", "timestamp=2025-01-12T00:07:57.972Z")
	if err != nil {
		t.Fatal(err)
	}
	if string(line) != "@time=2025-01-12T00:55:44.403Z :ergo.test MARKREAD #ergo timestamp=2025-01-12T00:07:57.972Z" {
		t.Errorf("got wrong line output: %s", line)
	}
}

func TestBuildPushMessage(t *testing.T) {
	now, err := time.Parse(utils.IRCv3TimestampFormat, "2025-01-12T01:05:04.422Z")
	if err != nil {
		panic(err)
	}

	lineBytes, err := MakePushMessage("PRIVMSG", "shivaram!~u@kca7nfgniet7q.irc", "shivaram", "#redacted", utils.SplitMessage{
		Message: "[redacted message contents]",
		Msgid:   "t8st5bb4b9qhed3zs3pwspinca",
		Time:    now,
	})
	if err != nil {
		t.Fatal(err)
	}
	line := string(lineBytes)
	parsed, err := ircmsg.ParseLineStrict(line, false, 512)
	if err != nil {
		t.Fatal(err)
	}
	if ok, account := parsed.GetTag("account"); !ok || account != "shivaram" {
		t.Fatalf("bad account tag %s", account)
	}
	if ok, timestamp := parsed.GetTag("time"); !ok || timestamp != "2025-01-12T01:05:04.422Z" {
		t.Fatal("bad time")
	}
	idx := strings.IndexByte(line, ' ')
	if line[idx+1:] != ":shivaram!~u@kca7nfgniet7q.irc PRIVMSG #redacted :[redacted message contents]" {
		t.Fatal("bad line")
	}
}
