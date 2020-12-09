// Copyright (c) 2018 Shivaram Lingamneni
// released under the MIT license

package connection_limits

import (
	"crypto/md5"
	"testing"
	"time"

	"github.com/oragono/oragono/irc/flatip"
)

func easyParseIP(ipstr string) (result flatip.IP) {
	result, err := flatip.ParseIP(ipstr)
	if err != nil {
		panic(err)
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
			"google": {
				Nets:          []string{"8.8.0.0/16"},
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

	// an ipv4 /32 looks like a /128 to us after applying the 4-in-6 mapping
	key, maxConc, maxWin := limiter.addrToKey(easyParseIP("1.1.1.1"))
	assertEqual(key.prefixLen, uint8(128), t)
	assertEqual(key.maskedIP[12:], []byte{1, 1, 1, 1}, t)
	assertEqual(maxConc, 4, t)
	assertEqual(maxWin, 8, t)

	testIPv6 := easyParseIP("2607:5301:201:3100::7426")
	key, maxConc, maxWin = limiter.addrToKey(testIPv6)
	assertEqual(key.prefixLen, uint8(64), t)
	assertEqual(flatip.IP(key.maskedIP), easyParseIP("2607:5301:201:3100::"), t)
	assertEqual(maxConc, 4, t)
	assertEqual(maxWin, 8, t)

	key, maxConc, maxWin = limiter.addrToKey(easyParseIP("8.8.4.4"))
	assertEqual(key.prefixLen, uint8(0), t)
	assertEqual([16]byte(key.maskedIP), md5.Sum([]byte("google")), t)
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
