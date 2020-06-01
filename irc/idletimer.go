// Copyright (c) 2017 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"fmt"
	"sync"
	"time"

	"github.com/oragono/oragono/irc/caps"
)

const (
	// RegisterTimeout is how long clients have to register before we disconnect them
	RegisterTimeout = time.Minute
	// DefaultIdleTimeout is how long without traffic before we send the client a PING
	DefaultIdleTimeout = time.Minute + 30*time.Second
	// For Tor clients, we send a PING at least every 30 seconds, as a workaround for this bug
	// (single-onion circuits will close unless the client sends data once every 60 seconds):
	// https://bugs.torproject.org/29665
	TorIdleTimeout = time.Second * 30
	// This is how long a client gets without sending any message, including the PONG to our
	// PING, before we disconnect them:
	DefaultTotalTimeout = 2*time.Minute + 30*time.Second
	// Resumeable clients (clients who have negotiated caps.Resume) get longer:
	ResumeableTotalTimeout = 3*time.Minute + 30*time.Second
)

// client idleness state machine

type TimerState uint

const (
	TimerUnregistered TimerState = iota // client is unregistered
	TimerActive                         // client is actively sending commands
	TimerIdle                           // client is idle, we sent PING and are waiting for PONG
	TimerDead                           // client was terminated
)

type IdleTimer struct {
	sync.Mutex // tier 1

	// immutable after construction
	registerTimeout time.Duration
	session         *Session

	// mutable
	idleTimeout time.Duration
	quitTimeout time.Duration
	state       TimerState
	timer       *time.Timer
}

// Initialize sets up an IdleTimer and starts counting idle time;
// if there is no activity from the client, it will eventually be stopped.
func (it *IdleTimer) Initialize(session *Session) {
	it.session = session
	it.registerTimeout = RegisterTimeout
	it.idleTimeout, it.quitTimeout = it.recomputeDurations()
	registered := session.client.Registered()

	it.Lock()
	defer it.Unlock()
	if registered {
		it.state = TimerActive
	} else {
		it.state = TimerUnregistered
	}
	it.resetTimeout()
}

// recomputeDurations recomputes the idle and quit durations, given the client's caps.
func (it *IdleTimer) recomputeDurations() (idleTimeout, quitTimeout time.Duration) {
	totalTimeout := DefaultTotalTimeout
	// if they have the resume cap, wait longer before pinging them out
	// to give them a chance to resume their connection
	if it.session.capabilities.Has(caps.Resume) {
		totalTimeout = ResumeableTotalTimeout
	}

	idleTimeout = DefaultIdleTimeout
	if it.session.isTor {
		idleTimeout = TorIdleTimeout
	}

	quitTimeout = totalTimeout - idleTimeout
	return
}

func (it *IdleTimer) Touch() {
	idleTimeout, quitTimeout := it.recomputeDurations()

	it.Lock()
	defer it.Unlock()
	it.idleTimeout, it.quitTimeout = idleTimeout, quitTimeout
	// a touch transitions TimerUnregistered or TimerIdle into TimerActive
	if it.state != TimerDead {
		it.state = TimerActive
		it.resetTimeout()
	}
}

func (it *IdleTimer) processTimeout() {
	idleTimeout, quitTimeout := it.recomputeDurations()

	var previousState TimerState
	func() {
		it.Lock()
		defer it.Unlock()
		it.idleTimeout, it.quitTimeout = idleTimeout, quitTimeout
		previousState = it.state
		// TimerActive transitions to TimerIdle, all others to TimerDead
		if it.state == TimerActive {
			// send them a ping, give them time to respond
			it.state = TimerIdle
			it.resetTimeout()
		} else {
			it.state = TimerDead
		}
	}()

	if previousState == TimerActive {
		it.session.Ping()
	} else {
		it.session.client.Quit(it.quitMessage(previousState), it.session)
		it.session.client.destroy(it.session)
	}
}

// Stop stops counting idle time.
func (it *IdleTimer) Stop() {
	if it == nil {
		return
	}

	it.Lock()
	defer it.Unlock()
	it.state = TimerDead
	it.resetTimeout()
}

func (it *IdleTimer) resetTimeout() {
	if it.timer != nil {
		it.timer.Stop()
	}
	var nextTimeout time.Duration
	switch it.state {
	case TimerUnregistered:
		nextTimeout = it.registerTimeout
	case TimerActive:
		nextTimeout = it.idleTimeout
	case TimerIdle:
		nextTimeout = it.quitTimeout
	case TimerDead:
		return
	}
	if it.timer != nil {
		it.timer.Reset(nextTimeout)
	} else {
		it.timer = time.AfterFunc(nextTimeout, it.processTimeout)
	}
}

func (it *IdleTimer) quitMessage(state TimerState) string {
	switch state {
	case TimerUnregistered:
		return fmt.Sprintf("Registration timeout: %v", it.registerTimeout)
	case TimerIdle:
		// how many seconds before registered clients are timed out (IdleTimeout plus QuitTimeout).
		it.Lock()
		defer it.Unlock()
		return fmt.Sprintf("Ping timeout: %v", (it.idleTimeout + it.quitTimeout))
	default:
		// shouldn't happen
		return ""
	}
}

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
