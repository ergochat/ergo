// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

// Package cloak implements IP address cloaking for IRC.
package cloak

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strings"

	"encoding/base32"
)

const (
	// MinKeyLength determines how many bytes our cloak keys should be, minimum.
	// This MUST NOT be higher in future releases, or else it will break existing,
	// working cloaking for everyone using key lengths this long.
	MinKeyLength = 32
	// partLength is how long each octet is after being base32'd.
	partLength = 10
)

var (
	errNetName             = errors.New("NetName is not the right size (must be 1-10 characters long)")
	errNotIPv4             = errors.New("The given address is not an IPv4 address")
	errConfigDisabled      = errors.New("Config has disabled IP cloaking")
	errKeysTooShort        = fmt.Errorf("Cloaking keys too short (min: %d)", MinKeyLength)
	errKeysNotRandomEnough = errors.New("Cloaking keys aren't random enough")
)

// Config controls whether we cloak, and if we do what values are used to do so.
type Config struct {
	// Enabled controls whether cloaking is performed.
	Enabled bool
	// NetName is the name used for the network in cloaked addresses.
	NetName string
	// IPv4KeyAString is used to cloak the `a` part of the IP address.
	IPv4KeyAString string `yaml:"ipv4-key-a"`
	IPv4KeyA       []byte
	// IPv4KeyBString is used to cloak the `b` part of the IP address.
	IPv4KeyBString string `yaml:"ipv4-key-b"`
	IPv4KeyB       []byte
	// IPv4KeyCString is used to cloak the `c` part of the IP address.
	IPv4KeyCString string `yaml:"ipv4-key-c"`
	IPv4KeyC       []byte
	// IPv4KeyDString is used to cloak the `d` part of the IP address.
	IPv4KeyDString string `yaml:"ipv4-key-d"`
	IPv4KeyD       []byte
}

// IsRandomEnough makes sure people are using keys that are random enough.
func IsRandomEnough(key []byte) bool {
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

// hashOctet does the heavy lifting in terms of hashing and returned an appropriate hashed octet
func hashOctet(key []byte, data string) string {
	sig := hmac.New(sha256.New, key)
	sig.Write([]byte(data))
	raw := sig.Sum(nil)
	return strings.ToLower(base32.StdEncoding.EncodeToString(raw))
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
func IPv4(address net.IP, config Config) (string, error) {
	if !config.Enabled {
		return "", errConfigDisabled
	}
	if len(config.NetName) < 1 || 10 < len(config.NetName) {
		return "", errNetName
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
	data := fmt.Sprintf("%d", partA)
	partAHashed := hashOctet(config.IPv4KeyA, data)[:partLength]

	// cloak `b` part of IP address.
	data = fmt.Sprintf("%d%d", partB, partA)
	partBHashed := hashOctet(config.IPv4KeyB, data)[:partLength]

	// cloak `c` part of IP address.
	data = fmt.Sprintf("%d%d%d", partC, partB, partA)
	partCHashed := hashOctet(config.IPv4KeyC, data)[:partLength]

	// cloak `d` part of IP address.
	data = fmt.Sprintf("%d%d%d%d", partD, partC, partB, partA)
	partDHashed := hashOctet(config.IPv4KeyD, data)[:partLength]

	return fmt.Sprintf("%s.%s.%s.%s.%s-cloaked", partAHashed, partBHashed, partCHashed, partDHashed, strings.ToLower(config.NetName)), nil
}
