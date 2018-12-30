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
	err := tListLong.RegenerateCachedReply()
	if err != nil {
		t.Error(err)
	}

	longReplies := [][]string{
		{"1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D"},
		{"E", "F"},
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
	err = tList1.RegenerateCachedReply()
	if err != nil {
		t.Error(err)
	}

	expected := [][]string{{"CASEMAPPING=rfc1459-strict", "EXTBAN", "INVEX=i", "RANDKILL=whenever", "SASL=yes"}}
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
	err = tList2.RegenerateCachedReply()
	if err != nil {
		t.Error(err)
	}

	expected = [][]string{{"CASEMAPPING=ascii", "EXTBAN=TestBah", "INVEX", "SASL=yes", "STABLEKILL"}}
	if !reflect.DeepEqual(tList2.CachedReply, expected) {
		t.Error("tList2's cached reply does not match expected cached reply")
	}

	// compare lists
	actual := tList1.GetDifference(tList2)
	expected = [][]string{{"-RANDKILL", "CASEMAPPING=ascii", "EXTBAN=TestBah", "INVEX", "STABLEKILL"}}
	if !reflect.DeepEqual(actual, expected) {
		t.Error("difference reply does not match expected difference reply")
	}
}

func TestBadToken(t *testing.T) {
	list := NewList()
	list.Add("NETWORK", "Bad Network Name")
	list.Add("SASL", "yes")
	list.Add("CASEMAPPING", "rfc1459-strict")
	list.Add("INVEX", "i")
	list.AddNoValue("EXTBAN")

	err := list.RegenerateCachedReply()
	if err == nil {
		t.Error("isupport token generation should fail due to space in network name")
	}

	// should produce a list containing the other, valid params
	numParams := 0
	for _, tokenLine := range list.CachedReply {
		numParams += len(tokenLine)
	}
	if numParams != 4 {
		t.Errorf("expected the other 4 params to be generated, got %v", list.CachedReply)
	}
}
