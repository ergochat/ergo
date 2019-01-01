// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package history

import (
	"reflect"
	"testing"
	"time"
)

const (
	timeFormat = "2006-01-02 15:04:05Z"
)

func TestEmptyBuffer(t *testing.T) {
	pastTime := easyParse(timeFormat)

	buf := NewHistoryBuffer(0)
	if buf.Enabled() {
		t.Error("the buffer of size 0 must be considered disabled")
	}

	buf.Add(Item{
		Nick: "testnick",
	})

	since, complete := buf.Between(pastTime, time.Now())
	if len(since) != 0 {
		t.Error("shouldn't be able to add to disabled buf")
	}
	if complete {
		t.Error("the empty/disabled buffer should report results as incomplete")
	}

	buf.Resize(1)
	if !buf.Enabled() {
		t.Error("the buffer of size 1 must be considered enabled")
	}
	since, complete = buf.Between(pastTime, time.Now())
	assertEqual(complete, true, t)
	assertEqual(len(since), 0, t)
	buf.Add(Item{
		Nick: "testnick",
	})
	since, complete = buf.Between(pastTime, time.Now())
	if len(since) != 1 {
		t.Error("should be able to store items in a nonempty buffer")
	}
	if !complete {
		t.Error("results should be complete")
	}
	if since[0].Nick != "testnick" {
		t.Error("retrived junk data")
	}

	buf.Add(Item{
		Nick: "testnick2",
	})
	since, complete = buf.Between(pastTime, time.Now())
	if len(since) != 1 {
		t.Error("expect exactly 1 item")
	}
	if complete {
		t.Error("results must be marked incomplete")
	}
	if since[0].Nick != "testnick2" {
		t.Error("retrieved junk data")
	}
	matchAll := func(item Item) bool { return true }
	assertEqual(toNicks(buf.Match(matchAll, 0)), []string{"testnick2"}, t)
}

func toNicks(items []Item) (result []string) {
	result = make([]string, len(items))
	for i, item := range items {
		result[i] = item.Nick
	}
	return
}

func easyParse(timestamp string) time.Time {
	result, err := time.Parse(timeFormat, timestamp)
	if err != nil {
		panic(err)
	}
	return result
}

func assertEqual(supplied, expected interface{}, t *testing.T) {
	if !reflect.DeepEqual(supplied, expected) {
		t.Errorf("expected %v but got %v", expected, supplied)
	}
}

func TestBuffer(t *testing.T) {
	start := easyParse("2006-01-01 00:00:00Z")

	buf := NewHistoryBuffer(3)
	buf.Add(Item{
		Nick: "testnick0",
		Time: easyParse("2006-01-01 15:04:05Z"),
	})

	buf.Add(Item{
		Nick: "testnick1",
		Time: easyParse("2006-01-02 15:04:05Z"),
	})

	buf.Add(Item{
		Nick: "testnick2",
		Time: easyParse("2006-01-03 15:04:05Z"),
	})

	since, complete := buf.Between(start, time.Now())
	assertEqual(complete, true, t)
	assertEqual(toNicks(since), []string{"testnick0", "testnick1", "testnick2"}, t)

	// add another item, evicting the first
	buf.Add(Item{
		Nick: "testnick3",
		Time: easyParse("2006-01-04 15:04:05Z"),
	})
	since, complete = buf.Between(start, time.Now())
	assertEqual(complete, false, t)
	assertEqual(toNicks(since), []string{"testnick1", "testnick2", "testnick3"}, t)
	// now exclude the time of the discarded entry; results should be complete again
	since, complete = buf.Between(easyParse("2006-01-02 00:00:00Z"), time.Now())
	assertEqual(complete, true, t)
	assertEqual(toNicks(since), []string{"testnick1", "testnick2", "testnick3"}, t)
	since, complete = buf.Between(easyParse("2006-01-02 00:00:00Z"), easyParse("2006-01-03 00:00:00Z"))
	assertEqual(complete, true, t)
	assertEqual(toNicks(since), []string{"testnick1"}, t)

	// shrink the buffer, cutting off testnick1
	buf.Resize(2)
	since, complete = buf.Between(easyParse("2006-01-02 00:00:00Z"), time.Now())
	assertEqual(complete, false, t)
	assertEqual(toNicks(since), []string{"testnick2", "testnick3"}, t)

	buf.Resize(5)
	buf.Add(Item{
		Nick: "testnick4",
		Time: easyParse("2006-01-05 15:04:05Z"),
	})
	buf.Add(Item{
		Nick: "testnick5",
		Time: easyParse("2006-01-06 15:04:05Z"),
	})
	buf.Add(Item{
		Nick: "testnick6",
		Time: easyParse("2006-01-07 15:04:05Z"),
	})
	since, complete = buf.Between(easyParse("2006-01-03 00:00:00Z"), time.Now())
	assertEqual(complete, true, t)
	assertEqual(toNicks(since), []string{"testnick2", "testnick3", "testnick4", "testnick5", "testnick6"}, t)
}
