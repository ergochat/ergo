// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"maps"
	"time"
)

// fakelag is a system for artificially delaying commands when a user issues
// them too rapidly

type FakelagState uint

const (
	// initially, the client is "bursting" and can send n commands without
	// encountering fakelag
	FakelagBursting FakelagState = iota
	// after that, they're "throttled" and we sleep in between commands until
	// they're spaced sufficiently far apart
	FakelagThrottled
)

// this is intentionally not threadsafe, because it should only be touched
// from the loop that accepts the client's input and runs commands
type Fakelag struct {
	config    FakelagConfig
	suspended bool
	nowFunc   func() time.Time
	sleepFunc func(time.Duration)

	state      FakelagState
	burstCount uint // number of messages sent in the current burst
	lastTouch  time.Time
}

func (fl *Fakelag) Initialize(config FakelagConfig) {
	fl.config = config
	// XXX don't share mutable member CommandBudgets:
	if config.CommandBudgets != nil {
		fl.config.CommandBudgets = maps.Clone(config.CommandBudgets)
	}
	fl.nowFunc = time.Now
	fl.sleepFunc = time.Sleep
	fl.state = FakelagBursting
}

// Idempotently turn off fakelag if it's enabled
func (fl *Fakelag) Suspend() {
	if fl.config.Enabled {
		fl.suspended = true
		fl.config.Enabled = false
	}
}

// Idempotently turn fakelag back on if it was previously Suspend'ed
func (fl *Fakelag) Unsuspend() {
	if fl.suspended {
		fl.config.Enabled = true
		fl.suspended = false
	}
}

// register a new command, sleep if necessary to delay it
func (fl *Fakelag) Touch(command string) {
	if !fl.config.Enabled {
		return
	}

	if budget, ok := fl.config.CommandBudgets[command]; ok && budget > 0 {
		fl.config.CommandBudgets[command] = budget - 1
		return
	}

	now := fl.nowFunc()
	// XXX if lastTouch.IsZero(), treat it as "very far in the past", which is fine
	elapsed := now.Sub(fl.lastTouch)
	fl.lastTouch = now

	if fl.state == FakelagBursting {
		// determine if the previous burst is over
		if elapsed > fl.config.Cooldown {
			fl.burstCount = 0
		}

		fl.burstCount++
		if fl.burstCount > fl.config.BurstLimit {
			// reset burst window for next time
			fl.burstCount = 0
			// transition to throttling
			fl.state = FakelagThrottled
			// continue to throttling logic
		} else {
			return
		}
	}

	if fl.state == FakelagThrottled {
		if elapsed > fl.config.Cooldown {
			// let them burst again
			fl.state = FakelagBursting
			fl.burstCount = 1
			return
		}
		var sleepDuration time.Duration
		if fl.config.MessagesPerWindow > 0 {
			// space them out by at least window/messagesperwindow
			sleepDuration = time.Duration((int64(fl.config.Window) / int64(fl.config.MessagesPerWindow)) - int64(elapsed))
		} else {
			// only burst messages are allowed: sleep until cooldown expires,
			// then count this as a burst message
			sleepDuration = time.Duration(int64(fl.config.Cooldown) - int64(elapsed))
			fl.state = FakelagBursting
			fl.burstCount = 1
		}
		if sleepDuration > 0 {
			fl.sleepFunc(sleepDuration)
			// the touch time should take into account the time we slept
			fl.lastTouch = fl.nowFunc()
		}
	}
}
