// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package connection_limits

import (
	"time"
)

// ThrottleDetails holds the connection-throttling details for a subnet/IP.
type ThrottleDetails struct {
	Start time.Time
	Count int
}

// GenericThrottle allows enforcing limits of the form
// "at most X events per time window of duration Y"
type GenericThrottle struct {
	ThrottleDetails // variable state: what events have been seen
	// these are constant after creation:
	Duration time.Duration // window length to consider
	Limit    int           // number of events allowed per window
}

// Touch checks whether an additional event is allowed:
// it either denies it (by returning false) or allows it (by returning true)
// and records it
func (g *GenericThrottle) Touch() (throttled bool, remainingTime time.Duration) {
	return g.touch(time.Now().UTC())
}

func (g *GenericThrottle) touch(now time.Time) (throttled bool, remainingTime time.Duration) {
	if g.Limit == 0 {
		return // limit of 0 disables throttling
	}

	elapsed := now.Sub(g.Start)
	if elapsed > g.Duration {
		// reset window, record the operation
		g.Start = now
		g.Count = 1
		return false, 0
	} else if g.Count >= g.Limit {
		// we are throttled
		return true, g.Start.Add(g.Duration).Sub(now)
	} else {
		// we are not throttled, record the operation
		g.Count += 1
		return false, 0
	}
}
