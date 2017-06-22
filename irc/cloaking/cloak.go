// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

// Package cloak implements IP address cloaking for IRC.
package cloak

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"crypto/sha512"
	"encoding/base64"
)

const (
	// MinKeyLength determines how many characters our cloak keys should be, minimum.
	// This MUST NOT be higher in future releases, or else it will break existing,
	// working cloaking for everyone using key lengths this long.
	MinKeyLength = 50
)

var (
	errNotIPv4             = errors.New("The given address is not an IPv4 address")
	errConfigDisabled      = errors.New("Config has disabled IP cloaking")
	errKeysTooShort        = fmt.Errorf("Cloaking keys too short (min: %d)", MinKeyLength)
	errKeysNotRandomEnough = errors.New("Cloaking keys aren't random enough")
)

// Config controls whether we cloak, and if we do what values are used to do so.
type Config struct {
	// Enabled controls whether cloaking is performed.
	Enabled bool
	// IPv4KeyA is used to cloak the `a` part of the IP address.
	IPv4KeyA string `yaml:"ipv4-key-a"`
	// IPv4KeyB is used to cloak the `b` part of the IP address.
	IPv4KeyB string `yaml:"ipv4-key-b"`
	// IPv4KeyC is used to cloak the `c` part of the IP address.
	IPv4KeyC string `yaml:"ipv4-key-c"`
	// IPv4KeyD is used to cloak the `d` part of the IP address.
	IPv4KeyD string `yaml:"ipv4-key-d"`
}

// IsRandomEnough makes sure people are using keys that are random enough.
func IsRandomEnough(key string) bool {
	return true
}

// toByteSlice is used for converting sha512 output from [64]byte to []byte.
func toByteSlice(orig [64]byte) []byte {
	var new []byte
	for _, val := range orig {
		new = append(new, val)
	}
	return new
}

// IPv4 returns a cloaked IPv4 address
//
// IPv4 addresses can be represented as a.b.c.d, where `a` is the least unique
// part of the address and `d` is the most unique part.
//
// `a` is unique for a given a.*.*.*, and `d` is unique for a given, specific
// a.b.c.d address. That is, if you have 1.2.3.4 and 2.3.4.4, the `d` part of
// both addresses should differ to prevent discoverability. In the same way,
// if you have 4.5.6.7 and 4.3.2.1 then the `a` part of those addresses will
// be the same value. This ensures chanops can properly ban dodgy people as
// they need to do so.
func IPv4(address net.IP, config Config, netName string) (string, error) {
	if !config.Enabled {
		return "", errConfigDisabled
	}

	// make sure the IP address is an IPv4 address.
	// from this point on we can assume `address` is a 4-byte slice
	if address.To4() == nil {
		return "", errNotIPv4
	}

	// check randomness of cloak keys
	if len(config.IPv4KeyA) < MinKeyLength || len(config.IPv4KeyB) < MinKeyLength || len(config.IPv4KeyC) < MinKeyLength || len(config.IPv4KeyD) < MinKeyLength {
		return "", errKeysTooShort
	}
	if !IsRandomEnough(config.IPv4KeyA) || !IsRandomEnough(config.IPv4KeyB) || !IsRandomEnough(config.IPv4KeyC) || !IsRandomEnough(config.IPv4KeyD) {
		return "", errKeysNotRandomEnough
	}

	// get IP parts
	address = address.To4()
	partA := address[0]
	partB := address[1]
	partC := address[2]
	partD := address[3]

	// cloak `a` part of IP address.
	fullKey := fmt.Sprintf("%d%s", partA, config.IPv4KeyA)
	cryptoHashedKey := toByteSlice(sha512.Sum512([]byte(fullKey)))
	partAHashed := strings.Trim(strings.Replace(base64.URLEncoding.EncodeToString(cryptoHashedKey), "_", "-", -1)[:16], "-")

	// cloak `b` part of IP address.
	fullKey = fmt.Sprintf("%d%d%s", partB, partA, config.IPv4KeyB)
	cryptoHashedKey = toByteSlice(sha512.Sum512([]byte(fullKey)))
	partBHashed := strings.Trim(strings.Replace(base64.URLEncoding.EncodeToString(cryptoHashedKey), "_", "-", -1)[:16], "-")

	// cloak `c` part of IP address.
	fullKey = fmt.Sprintf("%d%d%d%s", partC, partB, partA, config.IPv4KeyC)
	cryptoHashedKey = toByteSlice(sha512.Sum512([]byte(fullKey)))
	partCHashed := strings.Trim(strings.Replace(base64.URLEncoding.EncodeToString(cryptoHashedKey), "_", "-", -1)[:16], "-")

	// cloak `d` part of IP address.
	fullKey = fmt.Sprintf("%d%d%d%d%s", partD, partC, partB, partA, config.IPv4KeyD)
	cryptoHashedKey = toByteSlice(sha512.Sum512([]byte(fullKey)))
	partDHashed := strings.Trim(strings.Replace(base64.URLEncoding.EncodeToString(cryptoHashedKey), "_", "-", -1)[:16], "-")

	return fmt.Sprintf("%s.%s.%s.%s.cloaked-%s", partAHashed, partBHashed, partCHashed, partDHashed, netName), nil
}
