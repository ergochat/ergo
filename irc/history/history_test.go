// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package history

import (
	"reflect"
	"strconv"
	"testing"
	"time"
)

const (
	timeFormat = "2006-01-02 15:04:05Z"
)

func TestEmptyBuffer(t *testing.T) {
	pastTime := easyParse(timeFormat)

	buf := NewHistoryBuffer(0, 0)
	if buf.Enabled() {
		t.Error("the buffer of size 0 must be considered disabled")
	}

	buf.Add(Item{
		Nick: "testnick",
	})

	since, complete := buf.Between(pastTime, time.Now(), false, 0)
	if len(since) != 0 {
		t.Error("shouldn't be able to add to disabled buf")
	}
	if complete {
		t.Error("the empty/disabled buffer should report results as incomplete")
	}

	buf.Resize(1, 0)
	if !buf.Enabled() {
		t.Error("the buffer of size 1 must be considered enabled")
	}
	since, complete = buf.Between(pastTime, time.Now(), false, 0)
	assertEqual(complete, true, t)
	assertEqual(len(since), 0, t)
	buf.Add(Item{
		Nick: "testnick",
	})
	since, complete = buf.Between(pastTime, time.Now(), false, 0)
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
	since, complete = buf.Between(pastTime, time.Now(), false, 0)
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
	assertEqual(toNicks(buf.Match(matchAll, false, 0)), []string{"testnick2"}, t)
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

func easyItem(nick string, timestamp string) (result Item) {
	result.Message.Time = easyParse(timestamp)
	result.Nick = nick
	return
}

func assertEqual(supplied, expected interface{}, t *testing.T) {
	if !reflect.DeepEqual(supplied, expected) {
		t.Errorf("expected %v but got %v", expected, supplied)
	}
}

func TestBuffer(t *testing.T) {
	start := easyParse("2006-01-01 00:00:00Z")

	buf := NewHistoryBuffer(3, 0)
	buf.Add(easyItem("testnick0", "2006-01-01 15:04:05Z"))

	buf.Add(easyItem("testnick1", "2006-01-02 15:04:05Z"))

	buf.Add(easyItem("testnick2", "2006-01-03 15:04:05Z"))

	since, complete := buf.Between(start, time.Now(), false, 0)
	assertEqual(complete, true, t)
	assertEqual(toNicks(since), []string{"testnick0", "testnick1", "testnick2"}, t)

	// add another item, evicting the first
	buf.Add(easyItem("testnick3", "2006-01-04 15:04:05Z"))

	since, complete = buf.Between(start, time.Now(), false, 0)
	assertEqual(complete, false, t)
	assertEqual(toNicks(since), []string{"testnick1", "testnick2", "testnick3"}, t)
	// now exclude the time of the discarded entry; results should be complete again
	since, complete = buf.Between(easyParse("2006-01-02 00:00:00Z"), time.Now(), false, 0)
	assertEqual(complete, true, t)
	assertEqual(toNicks(since), []string{"testnick1", "testnick2", "testnick3"}, t)
	since, complete = buf.Between(easyParse("2006-01-02 00:00:00Z"), easyParse("2006-01-03 00:00:00Z"), false, 0)
	assertEqual(complete, true, t)
	assertEqual(toNicks(since), []string{"testnick1"}, t)

	// shrink the buffer, cutting off testnick1
	buf.Resize(2, 0)
	since, complete = buf.Between(easyParse("2006-01-02 00:00:00Z"), time.Now(), false, 0)
	assertEqual(complete, false, t)
	assertEqual(toNicks(since), []string{"testnick2", "testnick3"}, t)

	buf.Resize(5, 0)
	buf.Add(easyItem("testnick4", "2006-01-05 15:04:05Z"))
	buf.Add(easyItem("testnick5", "2006-01-06 15:04:05Z"))
	buf.Add(easyItem("testnick6", "2006-01-07 15:04:05Z"))
	since, complete = buf.Between(easyParse("2006-01-03 00:00:00Z"), time.Now(), false, 0)
	assertEqual(complete, true, t)
	assertEqual(toNicks(since), []string{"testnick2", "testnick3", "testnick4", "testnick5", "testnick6"}, t)

	// test ascending order
	since, _ = buf.Between(easyParse("2006-01-03 00:00:00Z"), time.Now(), true, 2)
	assertEqual(toNicks(since), []string{"testnick2", "testnick3"}, t)
}

func autoItem(id int, t time.Time) (result Item) {
	result.Message.Time = t
	result.Nick = strconv.Itoa(id)
	return
}

func atoi(s string) int {
	result, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return result
}

func TestAutoresize(t *testing.T) {
	now := easyParse("2006-01-01 00:00:00Z")
	nowFunc := func() time.Time {
		return now
	}

	buf := NewHistoryBuffer(128, time.Hour)
	buf.nowFunc = nowFunc

	// add items slowly (one every 10 minutes): the buffer should not expand
	// beyond initialAutoSize
	id := 0
	for i := 0; i < 72; i += 1 {
		buf.Add(autoItem(id, now))
		if initialAutoSize < buf.length() {
			t.Errorf("buffer incorrectly resized above %d to %d", initialAutoSize, buf.length())
		}
		now = now.Add(time.Minute * 10)
		id += 1
	}
	items := buf.Latest(0)
	assertEqual(len(items), initialAutoSize, t)
	assertEqual(atoi(items[0].Nick), 40, t)
	assertEqual(atoi(items[len(items)-1].Nick), 71, t)

	// dump 100 items in very fast:
	for i := 0; i < 100; i += 1 {
		buf.Add(autoItem(id, now))
		now = now.Add(time.Second)
		id += 1
	}
	// ok, 5 items from the first batch are still in the 1-hour window;
	// we should overwrite until only those 5 are left, then start expanding
	// the buffer so that it retains those 5 and the 100 new items
	items = buf.Latest(0)
	assertEqual(len(items), 105, t)
	assertEqual(atoi(items[0].Nick), 67, t)
	assertEqual(atoi(items[len(items)-1].Nick), 171, t)

	// another 100 items very fast:
	for i := 0; i < 100; i += 1 {
		buf.Add(autoItem(id, now))
		now = now.Add(time.Second)
		id += 1
	}
	// should fill up to the maximum size of 128 and start overwriting
	items = buf.Latest(0)
	assertEqual(len(items), 128, t)
	assertEqual(atoi(items[0].Nick), 144, t)
	assertEqual(atoi(items[len(items)-1].Nick), 271, t)
}

func TestRoundUp(t *testing.T) {
	assertEqual(roundUpToPowerOfTwo(2), 2, t)
	assertEqual(roundUpToPowerOfTwo(3), 4, t)
	assertEqual(roundUpToPowerOfTwo(64), 64, t)
	assertEqual(roundUpToPowerOfTwo(65), 128, t)
	assertEqual(roundUpToPowerOfTwo(100), 128, t)
	assertEqual(roundUpToPowerOfTwo(1000), 1024, t)
	assertEqual(roundUpToPowerOfTwo(1025), 2048, t)
	assertEqual(roundUpToPowerOfTwo(269435457), 536870912, t)
}
