// Copyright (c) 2019 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package connection_limits

import (
	"sync"
	"time"
)

// TorLimiter is a combined limiter and throttler for use on connections
// proxied from a Tor hidden service (so we don't have meaningful IPs,
// a notion of CIDR width, etc.)
type TorLimiter struct {
	sync.Mutex

	numConnections int
	maxConnections int
	throttle       GenericThrottle
}

func (tl *TorLimiter) Configure(maxConnections int, duration time.Duration, maxConnectionsPerDuration int) {
	tl.Lock()
	defer tl.Unlock()
	tl.maxConnections = maxConnections
	tl.throttle.Duration = duration
	tl.throttle.Limit = maxConnectionsPerDuration
}

func (tl *TorLimiter) AddClient() error {
	tl.Lock()
	defer tl.Unlock()

	if tl.maxConnections != 0 && tl.maxConnections <= tl.numConnections {
		return ErrLimitExceeded
	}
	throttled, _ := tl.throttle.Touch()
	if throttled {
		return ErrThrottleExceeded
	}
	tl.numConnections += 1
	return nil
}

func (tl *TorLimiter) RemoveClient() {
	tl.Lock()
	tl.numConnections -= 1
	tl.Unlock()
}
