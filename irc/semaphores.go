// Copyright (c) 2018 Shivaram Lingamneni

package irc

import (
	"log"
	"runtime"
	"runtime/debug"
)

// See #237 for context. Operations that might allocate large amounts of temporary
// garbage, or temporarily tie up some other resource, may cause thrashing unless
// their concurrency is artificially restricted. We use `chan bool` as a
// (regrettably, unary-encoded) counting semaphore to enforce these restrictions.

const (
	// this is a tradeoff between exploiting CPU-level parallelism (higher values better)
	// and not thrashing the allocator (lower values better). really this is all just
	// guesswork. oragono *can* make use of cores beyond this limit --- just not for
	// the protected operations.
	MaxServerSemaphoreCapacity = 32
)

// Semaphore is a counting semaphore. Note that a capacity of n requires O(n) storage.
type Semaphore (chan bool)

// ServerSemaphores includes a named Semaphore corresponding to each concurrency-limited
// sever operation.
type ServerSemaphores struct {
	// each distinct operation MUST have its own semaphore;
	// methods that acquire a semaphore MUST NOT call methods that acquire another
	ClientDestroy Semaphore
}

// NewServerSemaphores creates a new ServerSemaphores.
func NewServerSemaphores() (result *ServerSemaphores) {
	capacity := runtime.NumCPU()
	if capacity > MaxServerSemaphoreCapacity {
		capacity = MaxServerSemaphoreCapacity
	}
	result = new(ServerSemaphores)
	result.ClientDestroy.Initialize(capacity)
	return
}

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
