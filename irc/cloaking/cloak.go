// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

// Package cloak implements IP address cloaking for IRC.
package cloak

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	errKeysTooShort        = errors.New("Cloaking keys too short")
	errKeysNotRandomEnough = errors.New("Cloaking keys aren't random enough")
)

// Config controls whether we cloak, and if we do what values are used to do so.
type Config struct {
	// Enabled controls whether cloaking is performed.
	Enabled bool
	// NetName is the name used for the network in cloaked addresses.
	NetName string
	// IPv4KeyString is used to cloak the `a`, `b`, `c` and `d` parts of the IP address.
	// it is split up into the separate A/B/C/D keys below.
	IPv4KeysString []string `yaml:"ipv4-keys"`
	IPv4KeyA       []byte
	IPv4KeyB       []byte
	IPv4KeyC       []byte
	IPv4KeyD       []byte
}

// CheckConfig checks whether we're configured correctly.
func (config *Config) CheckConfig() error {
	if config.Enabled {
		// IPv4 cloak keys
		if len(config.IPv4KeysString) < 4 {
			return errKeysTooShort
		}

		keyA, errA := base64.StdEncoding.DecodeString(config.IPv4KeysString[0])
		keyB, errB := base64.StdEncoding.DecodeString(config.IPv4KeysString[1])
		keyC, errC := base64.StdEncoding.DecodeString(config.IPv4KeysString[2])
		keyD, errD := base64.StdEncoding.DecodeString(config.IPv4KeysString[3])

		if errA != nil || errB != nil || errC != nil || errD != nil {
			return fmt.Errorf("Could not decode IPv4 cloak keys")
		}
		if len(keyA) < MinKeyLength || len(keyB) < MinKeyLength || len(keyC) < MinKeyLength || len(keyD) < MinKeyLength {
			return errKeysTooShort
		}

		config.IPv4KeyA = keyA
		config.IPv4KeyB = keyB
		config.IPv4KeyC = keyC
		config.IPv4KeyD = keyD

		// try cloaking IPs to confirm everything works properly
		_, err := IPv4(net.ParseIP("8.8.8.8"), config)
		if err != nil {
			return err
		}
	}
	return nil
}

// GenerateCloakKey generates one cloak key.
func GenerateCloakKey() (string, error) {
	keyBytes := make([]byte, MinKeyLength)
	_, err := rand.Read(keyBytes)
	if err != nil {
		return "", fmt.Errorf("Could not generate random bytes for cloak key: %s", err.Error())
	}

	return base64.StdEncoding.EncodeToString(keyBytes), nil
}

// IsRandomEnough makes sure people are using keys that are random enough.
func IsRandomEnough(key []byte) bool {
	//TODO(dan): actually find out how to calc this
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
func IPv4(address net.IP, config *Config) (string, error) {
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
