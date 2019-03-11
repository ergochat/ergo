// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"testing"
	"time"
)

type mockTime struct {
	now              time.Time
	sleepList        []time.Duration
	lastCheckedSleep int
}

func (mt *mockTime) Now() (now time.Time) {
	return mt.now
}

func (mt *mockTime) Sleep(dur time.Duration) {
	mt.sleepList = append(mt.sleepList, dur)
	mt.pause(dur)
}

func (mt *mockTime) pause(dur time.Duration) {
	mt.now = mt.now.Add(dur)
}

func (mt *mockTime) lastSleep() (slept bool, duration time.Duration) {
	if mt.lastCheckedSleep == len(mt.sleepList)-1 {
		slept = false
		return
	}

	slept = true
	mt.lastCheckedSleep += 1
	duration = mt.sleepList[mt.lastCheckedSleep]
	return
}

func newFakelagForTesting(window time.Duration, burstLimit uint, throttleMessagesPerWindow uint, cooldown time.Duration) (*Fakelag, *mockTime) {
	fl := Fakelag{}
	fl.config = FakelagConfig{
		Enabled:           true,
		Window:            window,
		BurstLimit:        burstLimit,
		MessagesPerWindow: throttleMessagesPerWindow,
		Cooldown:          cooldown,
	}
	mt := new(mockTime)
	mt.now, _ = time.Parse("Mon Jan 2 15:04:05 -0700 MST 2006", "Mon Jan 2 15:04:05 -0700 MST 2006")
	mt.lastCheckedSleep = -1
	fl.nowFunc = mt.Now
	fl.sleepFunc = mt.Sleep
	return &fl, mt
}

func TestFakelag(t *testing.T) {
	window, _ := time.ParseDuration("1s")
	fl, mt := newFakelagForTesting(window, 3, 2, window)

	fl.Touch()
	slept, _ := mt.lastSleep()
	if slept {
		t.Fatalf("should not have slept")
	}

	interval, _ := time.ParseDuration("100ms")
	for i := 0; i < 2; i++ {
		mt.pause(interval)
		fl.Touch()
		slept, _ := mt.lastSleep()
		if slept {
			t.Fatalf("should not have slept")
		}
	}

	mt.pause(interval)
	fl.Touch()
	if fl.state != FakelagThrottled {
		t.Fatalf("should be throttled")
	}
	slept, duration := mt.lastSleep()
	if !slept {
		t.Fatalf("should have slept due to fakelag")
	}
	expected, _ := time.ParseDuration("400ms")
	if duration != expected {
		t.Fatalf("incorrect sleep time: %v != %v", expected, duration)
	}

	// send another message without a pause; we should have to sleep for 500 msec
	fl.Touch()
	if fl.state != FakelagThrottled {
		t.Fatalf("should be throttled")
	}
	slept, duration = mt.lastSleep()
	expected, _ = time.ParseDuration("500ms")
	if duration != expected {
		t.Fatalf("incorrect sleep time: %v != %v", duration, expected)
	}

	mt.pause(interval * 6)
	fl.Touch()
	if fl.state != FakelagThrottled {
		t.Fatalf("should still be throttled")
	}
	slept, duration = mt.lastSleep()
	if duration != 0 {
		t.Fatalf("we paused for long enough that we shouldn't sleep here")
	}

	mt.pause(window * 2)
	fl.Touch()
	if fl.state != FakelagBursting {
		t.Fatalf("should be bursting again")
	}
	slept, _ = mt.lastSleep()
	if slept {
		t.Fatalf("should not have slept")
	}
}
