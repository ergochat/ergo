// Copyright (c) 2017 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"fmt"
	"sync"
	"time"
)

// client idleness state machine

type TimerState uint

const (
	TimerUnregistered TimerState = iota // client is unregistered
	TimerActive                         // client is actively sending commands
	TimerIdle                           // client is idle, we sent PING and are waiting for PONG
)

type IdleTimer struct {
	sync.Mutex

	// immutable after construction
	registerTimeout time.Duration
	idleTimeout     time.Duration
	quitTimeout     time.Duration

	// mutable
	client   *Client
	state    TimerState
	lastSeen time.Time
}

// NewIdleTimer sets up a new IdleTimer using constant timeouts.
func NewIdleTimer(client *Client) *IdleTimer {
	it := IdleTimer{
		registerTimeout: RegisterTimeout,
		idleTimeout:     IdleTimeout,
		quitTimeout:     QuitTimeout,
		client:          client,
		state:           TimerUnregistered,
	}
	return &it
}

// Start starts counting idle time; if there is no activity from the client,
// it will eventually be stopped.
func (it *IdleTimer) Start() {
	it.Lock()
	it.lastSeen = time.Now()
	it.Unlock()
	go it.mainLoop()
}

func (it *IdleTimer) mainLoop() {
	for {
		it.Lock()
		client := it.client
		state := it.state
		lastSeen := it.lastSeen
		it.Unlock()

		if client == nil {
			return
		}

		registered := client.Registered()
		now := time.Now()
		idleTime := now.Sub(lastSeen)
		newState := state

		switch state {
		case TimerUnregistered:
			if registered {
				// transition to TimerActive state
				newState = TimerActive
			}
		case TimerActive:
			if idleTime >= IdleTimeout {
				newState = TimerIdle
				client.Ping()
			}
		case TimerIdle:
			if idleTime < IdleTimeout {
				// new ping came in after we transitioned to TimerIdle
				newState = TimerActive
			}
		}

		it.Lock()
		it.state = newState
		it.Unlock()

		var nextSleep time.Duration
		switch newState {
		case TimerUnregistered:
			nextSleep = it.registerTimeout - idleTime
		case TimerActive:
			nextSleep = it.idleTimeout - idleTime
		case TimerIdle:
			nextSleep = (it.idleTimeout + it.quitTimeout) - idleTime
		}

		if nextSleep <= 0 {
			// ran out of time, hang them up
			client.Quit(it.quitMessage(newState))
			client.destroy()
			return
		}

		time.Sleep(nextSleep)
	}
}

// Touch registers activity (e.g., sending a command) from an client.
func (it *IdleTimer) Touch() {
	it.Lock()
	client := it.client
	it.Unlock()

	// ignore touches for unregistered clients
	if client != nil && !client.Registered() {
		return
	}

	it.Lock()
	it.lastSeen = time.Now()
	it.Unlock()
}

// Stop stops counting idle time.
func (it *IdleTimer) Stop() {
	it.Lock()
	defer it.Unlock()
	// no need to stop the goroutine, it'll clean itself up in a few minutes;
	// just ensure the Client object is collectable
	it.client = nil
}

func (it *IdleTimer) quitMessage(state TimerState) string {
	switch state {
	case TimerUnregistered:
		return fmt.Sprintf("Registration timeout: %v", it.registerTimeout)
	case TimerIdle:
		// how many seconds before registered clients are timed out (IdleTimeout plus QuitTimeout).
		return fmt.Sprintf("Ping timeout: %v", (it.idleTimeout + it.quitTimeout))
	default:
		// shouldn't happen
		return ""
	}
}
