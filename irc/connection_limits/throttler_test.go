// Copyright (c) 2018 Shivaram Lingamneni
// released under the MIT license

package connection_limits

import (
	"net"
	"reflect"
	"testing"
	"time"
)

func assertEqual(supplied, expected interface{}, t *testing.T) {
	if !reflect.DeepEqual(supplied, expected) {
		t.Errorf("expected %v but got %v", expected, supplied)
	}
}

func TestGenericThrottle(t *testing.T) {
	minute, _ := time.ParseDuration("1m")
	second, _ := time.ParseDuration("1s")
	zero, _ := time.ParseDuration("0s")

	throttler := GenericThrottle{
		Duration: minute,
		Limit:    2,
	}

	now := time.Now()
	throttled, remaining := throttler.touch(now)
	assertEqual(throttled, false, t)
	assertEqual(remaining, zero, t)

	now = now.Add(second)
	throttled, remaining = throttler.touch(now)
	assertEqual(throttled, false, t)
	assertEqual(remaining, zero, t)

	now = now.Add(second)
	throttled, remaining = throttler.touch(now)
	assertEqual(throttled, true, t)
	assertEqual(remaining, 58*second, t)

	now = now.Add(minute)
	throttled, remaining = throttler.touch(now)
	assertEqual(throttled, false, t)
	assertEqual(remaining, zero, t)
}

func TestGenericThrottleDisabled(t *testing.T) {
	minute, _ := time.ParseDuration("1m")
	throttler := GenericThrottle{
		Duration: minute,
		Limit:    0,
	}

	for i := 0; i < 1024; i += 1 {
		throttled, _ := throttler.Touch()
		if throttled {
			t.Error("disabled throttler should not throttle")
		}
	}
}

func TestConnectionThrottle(t *testing.T) {
	minute, _ := time.ParseDuration("1m")
	maxConnections := 3
	config := ThrottlerConfig{
		Enabled:            true,
		CidrLenIPv4:        32,
		CidrLenIPv6:        64,
		ConnectionsPerCidr: maxConnections,
		Duration:           minute,
	}
	throttler := NewThrottler()
	throttler.ApplyConfig(config)

	addr := net.ParseIP("8.8.8.8")

	for i := 0; i < maxConnections; i += 1 {
		err := throttler.AddClient(addr)
		assertEqual(err, nil, t)
	}
	err := throttler.AddClient(addr)
	assertEqual(err, errTooManyClients, t)
}
