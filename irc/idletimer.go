// Copyright (c) 2017 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goshuirc/irc-go/ircfmt"
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
	if it.session.client.isTor {
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

// NickTimer manages timing out of clients who are squatting reserved nicks
type NickTimer struct {
	sync.Mutex // tier 1

	// immutable after construction
	client *Client

	// mutable
	nick           string
	accountForNick string
	account        string
	timeout        time.Duration
	timer          *time.Timer
	enabled        uint32
}

// Initialize sets up a NickTimer, based on server config settings.
func (nt *NickTimer) Initialize(client *Client) {
	if nt.client == nil {
		nt.client = client // placate the race detector
	}

	config := &client.server.Config().Accounts.NickReservation
	enabled := config.Enabled && (config.Method == NickEnforcementWithTimeout || config.AllowCustomEnforcement)

	nt.Lock()
	defer nt.Unlock()
	nt.timeout = config.RenameTimeout
	if enabled {
		atomic.StoreUint32(&nt.enabled, 1)
	} else {
		nt.stopInternal()
	}
}

func (nt *NickTimer) Enabled() bool {
	return atomic.LoadUint32(&nt.enabled) == 1
}

func (nt *NickTimer) Timeout() (timeout time.Duration) {
	nt.Lock()
	timeout = nt.timeout
	nt.Unlock()
	return
}

// Touch records a nick change and updates the timer as necessary
func (nt *NickTimer) Touch(rb *ResponseBuffer) {
	if !nt.Enabled() {
		return
	}

	var session *Session
	if rb != nil {
		session = rb.session
	}

	cfnick, skeleton := nt.client.uniqueIdentifiers()
	account := nt.client.Account()
	accountForNick, method := nt.client.server.accounts.EnforcementStatus(cfnick, skeleton)
	enforceTimeout := method == NickEnforcementWithTimeout

	var shouldWarn, shouldRename bool

	func() {
		nt.Lock()
		defer nt.Unlock()

		// the timer will not reset as long as the squatter is targeting the same account
		accountChanged := accountForNick != nt.accountForNick
		// change state
		nt.nick = cfnick
		nt.account = account
		nt.accountForNick = accountForNick
		delinquent := accountForNick != "" && accountForNick != account

		if nt.timer != nil && (!enforceTimeout || !delinquent || accountChanged) {
			nt.timer.Stop()
			nt.timer = nil
		}
		if enforceTimeout && delinquent && (accountChanged || nt.timer == nil) {
			nt.timer = time.AfterFunc(nt.timeout, nt.processTimeout)
			shouldWarn = true
		} else if method == NickEnforcementStrict && delinquent {
			shouldRename = true // this can happen if reservation was enabled by rehash
		}
	}()

	if shouldWarn {
		tnick := nt.client.Nick()
		message := fmt.Sprintf(ircfmt.Unescape(nt.client.t(nsTimeoutNotice)), nt.Timeout())
		// #449
		for _, mSession := range nt.client.Sessions() {
			if mSession == session {
				rb.Add(nil, nsPrefix, "NOTICE", tnick, message)
				rb.Add(nil, nt.client.server.name, "WARN", "*", "ACCOUNT_REQUIRED", message)
			} else {
				mSession.Send(nil, nsPrefix, "NOTICE", tnick, message)
				mSession.Send(nil, nt.client.server.name, "WARN", "*", "ACCOUNT_REQUIRED", message)
			}
		}
	} else if shouldRename {
		nt.client.Notice(nt.client.t("Nickname is reserved by a different account"))
		nt.client.server.RandomlyRename(nt.client)
	}
}

// Stop stops counting time and cleans up the timer
func (nt *NickTimer) Stop() {
	nt.Lock()
	defer nt.Unlock()
	nt.stopInternal()
}

func (nt *NickTimer) stopInternal() {
	if nt.timer != nil {
		nt.timer.Stop()
		nt.timer = nil
	}
	atomic.StoreUint32(&nt.enabled, 0)
}

func (nt *NickTimer) processTimeout() {
	baseMsg := "Nick is reserved and authentication timeout expired: %v"
	nt.client.Notice(fmt.Sprintf(nt.client.t(baseMsg), nt.Timeout()))
	nt.client.server.RandomlyRename(nt.client)
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
	// BrbSticky allows a client to remain online without sessions, with no timeout.
	// This is not used yet.
	BrbSticky
)

type BrbTimer struct {
	// XXX we use client.stateMutex for synchronization, so we can atomically test
	// conditions that use both brbTimer.state and client.sessions. This code
	// is tightly coupled with the rest of Client.
	client *Client

	state    BrbState
	duration time.Duration
	timer    *time.Timer
}

func (bt *BrbTimer) Initialize(client *Client) {
	bt.client = client
}

// attempts to enable BRB for a client, returns whether it succeeded
func (bt *BrbTimer) Enable() (success bool, duration time.Duration) {
	// BRB only makes sense if a new connection can attach to the session;
	// this can happen either via RESUME or via bouncer reattach
	if bt.client.Account() == "" && bt.client.ResumeID() == "" {
		return
	}

	// TODO make this configurable
	duration = ResumeableTotalTimeout

	bt.client.stateMutex.Lock()
	defer bt.client.stateMutex.Unlock()

	switch bt.state {
	case BrbDisabled, BrbEnabled:
		bt.state = BrbEnabled
		bt.duration = duration
		bt.resetTimeout()
		success = true
	case BrbSticky:
		success = true
	default:
		// BrbDead
		success = false
	}
	return
}

// turns off BRB for a client and stops the timer; used on resume and during
// client teardown
func (bt *BrbTimer) Disable() {
	bt.client.stateMutex.Lock()
	defer bt.client.stateMutex.Unlock()

	if bt.state == BrbEnabled {
		bt.state = BrbDisabled
	}
	bt.resetTimeout()
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

	switch bt.state {
	case BrbDisabled, BrbEnabled:
		if len(bt.client.sessions) == 0 {
			// client never returned, quit them
			bt.state = BrbDead
			dead = true
		} else {
			// client resumed, reattached, or has another active session
			bt.state = BrbDisabled
		}
	case BrbDead:
		dead = true // shouldn't be possible but whatever
	}
	bt.resetTimeout()
}

// sets a client to be "sticky", i.e., indefinitely exempt from removal for
// lack of sessions
func (bt *BrbTimer) SetSticky() (success bool) {
	bt.client.stateMutex.Lock()
	defer bt.client.stateMutex.Unlock()
	if bt.state != BrbDead {
		success = true
		bt.state = BrbSticky
	}
	bt.resetTimeout()
	return
}
