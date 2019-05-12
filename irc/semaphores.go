// Copyright (c) 2018 Shivaram Lingamneni

package irc

import (
	"runtime"

	"github.com/oragono/oragono/irc/utils"
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

// ServerSemaphores includes a named Semaphore corresponding to each concurrency-limited
// sever operation.
type ServerSemaphores struct {
	// each distinct operation MUST have its own semaphore;
	// methods that acquire a semaphore MUST NOT call methods that acquire another
	ClientDestroy utils.Semaphore
}

// Initialize initializes a set of server semaphores.
func (serversem *ServerSemaphores) Initialize() {
	capacity := runtime.NumCPU()
	if capacity > MaxServerSemaphoreCapacity {
		capacity = MaxServerSemaphoreCapacity
	}
	serversem.ClientDestroy.Initialize(capacity)
}
