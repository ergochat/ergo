// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utils

import (
	"sync"
	"sync/atomic"
)

// Once is a fork of sync.Once to expose a Done() method.
type Once struct {
	done uint32
	m    sync.Mutex
}

func (o *Once) Do(f func()) {
	if atomic.LoadUint32(&o.done) == 0 {
		o.doSlow(f)
	}
}

func (o *Once) doSlow(f func()) {
	o.m.Lock()
	defer o.m.Unlock()
	if o.done == 0 {
		defer atomic.StoreUint32(&o.done, 1)
		f()
	}
}

func (o *Once) Done() bool {
	return atomic.LoadUint32(&o.done) == 1
}
