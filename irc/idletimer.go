// Copyright (c) 2017 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"time"
)

// BrbTimer is a timer on the client as a whole (not an individual session) for implementing
// the BRB command and related functionality (where a client can remain online without
// having any connected sessions).

type BrbState uint

const (
	// BrbDisabled is the default state; the client will be disconnected if it has no sessions
	BrbDisabled BrbState = iota
	// BrbEnabled allows the client to remain online without sessions; if a timeout is
	// reached, it will be removed
	BrbEnabled
	// BrbDead is the state of a client after its timeout has expired; it will be removed
	// and therefore new sessions cannot be attached to it
	BrbDead
)

type BrbTimer struct {
	// XXX we use client.stateMutex for synchronization, so we can atomically test
	// conditions that use both brbTimer.state and client.sessions. This code
	// is tightly coupled with the rest of Client.
	client *Client

	state    BrbState
	brbAt    time.Time
	duration time.Duration
	timer    *time.Timer
}

func (bt *BrbTimer) Initialize(client *Client) {
	bt.client = client
}

// attempts to enable BRB for a client, returns whether it succeeded
func (bt *BrbTimer) Enable() (success bool, duration time.Duration) {
	// TODO make this configurable
	duration = ResumeableTotalTimeout

	bt.client.stateMutex.Lock()
	defer bt.client.stateMutex.Unlock()

	if !bt.client.registered || bt.client.alwaysOn || bt.client.resumeID == "" {
		return
	}

	switch bt.state {
	case BrbDisabled, BrbEnabled:
		bt.state = BrbEnabled
		bt.duration = duration
		bt.resetTimeout()
		// only track the earliest BRB, if multiple sessions are BRB'ing at once
		// TODO(#524) this is inaccurate in case of an auto-BRB
		if bt.brbAt.IsZero() {
			bt.brbAt = time.Now().UTC()
		}
		success = true
	default:
		// BrbDead
		success = false
	}
	return
}

// turns off BRB for a client and stops the timer; used on resume and during
// client teardown
func (bt *BrbTimer) Disable() (brbAt time.Time) {
	bt.client.stateMutex.Lock()
	defer bt.client.stateMutex.Unlock()

	if bt.state == BrbEnabled {
		bt.state = BrbDisabled
		brbAt = bt.brbAt
		bt.brbAt = time.Time{}
	}
	bt.resetTimeout()
	return
}

func (bt *BrbTimer) resetTimeout() {
	if bt.timer != nil {
		bt.timer.Stop()
	}
	if bt.state != BrbEnabled {
		return
	}
	if bt.timer == nil {
		bt.timer = time.AfterFunc(bt.duration, bt.processTimeout)
	} else {
		bt.timer.Reset(bt.duration)
	}
}

func (bt *BrbTimer) processTimeout() {
	dead := false
	defer func() {
		if dead {
			bt.client.Quit(bt.client.AwayMessage(), nil)
			bt.client.destroy(nil)
		}
	}()

	bt.client.stateMutex.Lock()
	defer bt.client.stateMutex.Unlock()

	if bt.client.alwaysOn {
		return
	}

	switch bt.state {
	case BrbDisabled, BrbEnabled:
		if len(bt.client.sessions) == 0 {
			// client never returned, quit them
			bt.state = BrbDead
			dead = true
		} else {
			// client resumed, reattached, or has another active session
			bt.state = BrbDisabled
			bt.brbAt = time.Time{}
		}
	case BrbDead:
		dead = true // shouldn't be possible but whatever
	}
	bt.resetTimeout()
}
