// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"testing"
)

func makeTestWhowas(nick string) WhoWas {
	cfnick, err := CasefoldName(nick)
	if err != nil {
		panic(err)
	}
	return WhoWas{
		nicknameCasefolded: cfnick,
		nickname:           nick,
		username:           "user",
		hostname:           "oragono.io",
		realname:           "Real Name",
	}
}

func TestWhoWas(t *testing.T) {
	var results []WhoWas
	wwl := NewWhoWasList(3)
	// test Find on empty list
	results = wwl.Find("nobody", 10)
	if len(results) != 0 {
		t.Fatalf("incorrect whowas results: %v", results)
	}

	wwl.Append(makeTestWhowas("dan-"))
	results = wwl.Find("nobody", 10)
	if len(results) != 0 {
		t.Fatalf("incorrect whowas results: %v", results)
	}
	results = wwl.Find("dan-", 10)
	if len(results) != 1 || results[0].nickname != "dan-" {
		t.Fatalf("incorrect whowas results: %v", results)
	}

	wwl.Append(makeTestWhowas("slingamn"))
	results = wwl.Find("slingamN", 10)
	if len(results) != 1 || results[0].nickname != "slingamn" {
		t.Fatalf("incorrect whowas results: %v", results)
	}

	wwl.Append(makeTestWhowas("Dan-"))
	results = wwl.Find("dan-", 10)
	// reverse chronological order
	if len(results) != 2 || results[0].nickname != "Dan-" || results[1].nickname != "dan-" {
		t.Fatalf("incorrect whowas results: %v", results)
	}
	// 0 means no limit
	results = wwl.Find("dan-", 0)
	if len(results) != 2 || results[0].nickname != "Dan-" || results[1].nickname != "dan-" {
		t.Fatalf("incorrect whowas results: %v", results)
	}
	// a limit of 1 should return the most recent entry only
	results = wwl.Find("dan-", 1)
	if len(results) != 1 || results[0].nickname != "Dan-" {
		t.Fatalf("incorrect whowas results: %v", results)
	}

	wwl.Append(makeTestWhowas("moocow"))
	results = wwl.Find("moocow", 10)
	if len(results) != 1 || results[0].nickname != "moocow" {
		t.Fatalf("incorrect whowas results: %v", results)
	}
	results = wwl.Find("dan-", 10)
	// should have overwritten the original entry, leaving the second
	if len(results) != 1 || results[0].nickname != "Dan-" {
		t.Fatalf("incorrect whowas results: %v", results)
	}

	// overwrite the second entry
	wwl.Append(makeTestWhowas("enckse"))
	results = wwl.Find("enckse", 10)
	if len(results) != 1 || results[0].nickname != "enckse" {
		t.Fatalf("incorrect whowas results: %v", results)
	}
	results = wwl.Find("slingamn", 10)
	if len(results) != 0 {
		t.Fatalf("incorrect whowas results: %v", results)
	}
}


func TestEmptyWhoWas(t *testing.T) {
	// stupid edge case; setting an empty whowas buffer should not panic
	wwl := NewWhoWasList(0)
	results := wwl.Find("slingamn", 10)
	if len(results) != 0 {
		t.Fatalf("incorrect whowas results: %v", results)
	}
	wwl.Append(makeTestWhowas("slingamn"))
	results = wwl.Find("slingamn", 10)
	if len(results) != 0 {
		t.Fatalf("incorrect whowas results: %v", results)
	}
}
