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

func makeTestThrottler(v4len, v6len int) *Limiter {
	minute, _ := time.ParseDuration("1m")
	maxConnections := 3
	config := LimiterConfig{
		rawLimiterConfig: rawLimiterConfig{
			Count:        false,
			Throttle:     true,
			CidrLenIPv4:  v4len,
			CidrLenIPv6:  v6len,
			MaxPerWindow: maxConnections,
			Window:       minute,
		},
	}
	config.postprocess()
	var limiter Limiter
	limiter.ApplyConfig(&config)
	return &limiter
}

func TestConnectionThrottle(t *testing.T) {
	throttler := makeTestThrottler(32, 64)
	addr := net.ParseIP("8.8.8.8")

	for i := 0; i < 3; i += 1 {
		err := throttler.AddClient(addr)
		assertEqual(err, nil, t)
	}
	err := throttler.AddClient(addr)
	assertEqual(err, ErrThrottleExceeded, t)
}

func TestConnectionThrottleIPv6(t *testing.T) {
	throttler := makeTestThrottler(32, 64)

	var err error
	err = throttler.AddClient(net.ParseIP("2001:0db8::1"))
	assertEqual(err, nil, t)
	err = throttler.AddClient(net.ParseIP("2001:0db8::2"))
	assertEqual(err, nil, t)
	err = throttler.AddClient(net.ParseIP("2001:0db8::3"))
	assertEqual(err, nil, t)

	err = throttler.AddClient(net.ParseIP("2001:0db8::4"))
	assertEqual(err, ErrThrottleExceeded, t)
}

func TestConnectionThrottleIPv4(t *testing.T) {
	throttler := makeTestThrottler(24, 64)

	var err error
	err = throttler.AddClient(net.ParseIP("192.168.1.101"))
	assertEqual(err, nil, t)
	err = throttler.AddClient(net.ParseIP("192.168.1.102"))
	assertEqual(err, nil, t)
	err = throttler.AddClient(net.ParseIP("192.168.1.103"))
	assertEqual(err, nil, t)

	err = throttler.AddClient(net.ParseIP("192.168.1.104"))
	assertEqual(err, ErrThrottleExceeded, t)
}
