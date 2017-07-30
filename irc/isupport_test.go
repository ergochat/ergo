// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"reflect"
	"testing"
)

func TestISUPPORT(t *testing.T) {
	// create first list
	tList1 := NewISupportList()
	tList1.Add("SASL", "yes")
	tList1.Add("CASEMAPPING", "rfc1459-strict")
	tList1.Add("INVEX", "i")
	tList1.AddNoValue("EXTBAN")
	tList1.Add("RANDKILL", "whenever")
	tList1.RegenerateCachedReply()

	expected := [][]string{{"CASEMAPPING=rfc1459-strict", "EXTBAN", "INVEX=i", "RANDKILL=whenever", "SASL=yes", "are supported by this server"}}
	if !reflect.DeepEqual(tList1.CachedReply, expected) {
		t.Error("tList1's cached reply does not match expected cached reply")
	}

	// create second list
	tList2 := NewISupportList()
	tList2.Add("SASL", "yes")
	tList2.Add("CASEMAPPING", "ascii")
	tList2.AddNoValue("INVEX")
	tList2.Add("EXTBAN", "TestBah")
	tList2.AddNoValue("STABLEKILL")
	tList2.RegenerateCachedReply()

	expected = [][]string{{"CASEMAPPING=ascii", "EXTBAN=TestBah", "INVEX", "SASL=yes", "STABLEKILL", "are supported by this server"}}
	if !reflect.DeepEqual(tList2.CachedReply, expected) {
		t.Error("tList2's cached reply does not match expected cached reply")
	}

	// compare lists
	actual := tList1.GetDifference(tList2)
	expected = [][]string{{"-RANDKILL", "CASEMAPPING=ascii", "EXTBAN=TestBah", "INVEX", "STABLEKILL", "are supported by this server"}}
	if !reflect.DeepEqual(actual, expected) {
		t.Error("difference reply does not match expected difference reply")
	}
}
