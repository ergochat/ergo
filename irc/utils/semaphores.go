// Copyright (c) 2018 Shivaram Lingamneni
// released under the MIT license

package utils

import (
	"log"
	"runtime/debug"
	"time"
)

// Semaphore is a counting semaphore. Note that a capacity of n requires O(n) storage.
// A semaphore of capacity 1 can be used as a trylock.
type Semaphore (chan bool)

// Initialize initializes a semaphore to a given capacity.
func (semaphore *Semaphore) Initialize(capacity int) {
	*semaphore = make(chan bool, capacity)
	for i := 0; i < capacity; i++ {
		(*semaphore) <- true
	}
}

// Acquire acquires a semaphore, blocking if necessary.
func (semaphore *Semaphore) Acquire() {
	<-(*semaphore)
}

// TryAcquire tries to acquire a semaphore, returning whether the acquire was
// successful. It never blocks.
func (semaphore *Semaphore) TryAcquire() (acquired bool) {
	select {
	case <-(*semaphore):
		return true
	default:
		return false
	}
}

// AcquireWithTimeout tries to acquire a semaphore, blocking for a maximum
// of approximately `d` while waiting for it. It returns whether the acquire
// was successful.
func (semaphore *Semaphore) AcquireWithTimeout(timeout time.Duration) (acquired bool) {
	if timeout < 0 {
		return semaphore.TryAcquire()
	}

	timer := time.NewTimer(timeout)
	select {
	case <-(*semaphore):
		acquired = true
	case <-timer.C:
		acquired = false
	}
	timer.Stop()
	return
}

// Release releases a semaphore. It never blocks. (This is not a license
// to program spurious releases.)
func (semaphore *Semaphore) Release() {
	select {
	case (*semaphore) <- true:
		// good
	default:
		// spurious release
		log.Printf("spurious semaphore release (full to capacity %d)", cap(*semaphore))
		debug.PrintStack()
	}
}
