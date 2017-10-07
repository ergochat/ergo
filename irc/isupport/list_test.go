// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package isupport

import (
	"reflect"
	"testing"
)

func TestISUPPORT(t *testing.T) {
	// test multiple output replies
	tListLong := NewList()
	tListLong.AddNoValue("1")
	tListLong.AddNoValue("2")
	tListLong.AddNoValue("3")
	tListLong.AddNoValue("4")
	tListLong.AddNoValue("5")
	tListLong.AddNoValue("6")
	tListLong.AddNoValue("7")
	tListLong.AddNoValue("8")
	tListLong.AddNoValue("9")
	tListLong.AddNoValue("A")
	tListLong.AddNoValue("B")
	tListLong.AddNoValue("C")
	tListLong.AddNoValue("D")
	tListLong.AddNoValue("E")
	tListLong.AddNoValue("F")
	tListLong.RegenerateCachedReply()

	longReplies := [][]string{
		{"1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "are supported by this server"},
		{"E", "F", "are supported by this server"},
	}

	if !reflect.DeepEqual(tListLong.CachedReply, longReplies) {
		t.Errorf("Multiple output replies did not match, got [%v]", longReplies)
	}

	// create first list
	tList1 := NewList()
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
	tList2 := NewList()
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
