// Copyright (c) 2019 Shivaram Lingamneni
// released under the MIT license

package utils

import (
	"testing"
	"time"
)

func TestTryAcquire(t *testing.T) {
	count := 3
	var sem Semaphore
	sem.Initialize(count)

	for i := 0; i < count; i++ {
		assertEqual(sem.TryAcquire(), true, t)
	}
	// used up the capacity
	assertEqual(sem.TryAcquire(), false, t)
	sem.Release()
	// got one slot back
	assertEqual(sem.TryAcquire(), true, t)
}

func TestAcquireWithTimeout(t *testing.T) {
	var sem Semaphore
	sem.Initialize(1)

	assertEqual(sem.TryAcquire(), true, t)

	// cannot acquire the held semaphore
	assertEqual(sem.AcquireWithTimeout(100*time.Millisecond), false, t)

	sem.Release()
	// can acquire the released semaphore
	assertEqual(sem.AcquireWithTimeout(100*time.Millisecond), true, t)
	sem.Release()

	// XXX this test could fail if the machine is extremely overloaded
	sem.Acquire()
	go func() {
		time.Sleep(100 * time.Millisecond)
		sem.Release()
	}()
	// we should acquire successfully after approximately 100 msec
	assertEqual(sem.AcquireWithTimeout(1*time.Second), true, t)
}
