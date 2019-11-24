// Copyright (c) 2018 Shivaram Lingamneni
// released under the MIT license

package connection_limits

import (
	"net"
	"testing"
	"time"
)

func easyParseIP(ipstr string) (result net.IP) {
	result = net.ParseIP(ipstr)
	if result == nil {
		panic(ipstr)
	}
	return
}

var baseConfig = LimiterConfig{
	rawLimiterConfig: rawLimiterConfig{
		Count:         true,
		MaxConcurrent: 4,

		Throttle:     true,
		Window:       time.Second * 600,
		MaxPerWindow: 8,

		CidrLenIPv4: 32,
		CidrLenIPv6: 64,

		Exempted: []string{"localhost"},

		CustomLimits: map[string]CustomLimitConfig{
			"8.8.0.0/16": {
				MaxConcurrent: 128,
				MaxPerWindow:  256,
			},
		},
	},
}

func TestKeying(t *testing.T) {
	config := baseConfig
	config.postprocess()
	var limiter Limiter
	limiter.ApplyConfig(&config)

	key, maxConc, maxWin := limiter.addrToKey(easyParseIP("1.1.1.1"))
	assertEqual(key, "1.1.1.1/32", t)
	assertEqual(maxConc, 4, t)
	assertEqual(maxWin, 8, t)

	key, maxConc, maxWin = limiter.addrToKey(easyParseIP("2607:5301:201:3100::7426"))
	assertEqual(key, "2607:5301:201:3100::/64", t)
	assertEqual(maxConc, 4, t)
	assertEqual(maxWin, 8, t)

	key, maxConc, maxWin = limiter.addrToKey(easyParseIP("8.8.4.4"))
	assertEqual(key, "8.8.0.0/16", t)
	assertEqual(maxConc, 128, t)
	assertEqual(maxWin, 256, t)
}

func TestLimits(t *testing.T) {
	regularIP := easyParseIP("2607:5301:201:3100::7426")
	config := baseConfig
	config.postprocess()
	var limiter Limiter
	limiter.ApplyConfig(&config)

	for i := 0; i < 4; i++ {
		err := limiter.AddClient(regularIP)
		if err != nil {
			t.Errorf("ip should not be blocked, but %v", err)
		}
	}
	err := limiter.AddClient(regularIP)
	if err != ErrLimitExceeded {
		t.Errorf("ip should be blocked, but %v", err)
	}
	limiter.RemoveClient(regularIP)
	err = limiter.AddClient(regularIP)
	if err != nil {
		t.Errorf("ip should not be blocked, but %v", err)
	}
}
