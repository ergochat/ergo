// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
)

var (
	// slingamn's own private b32 alphabet, removing 1, l, o, and 0
	b32encoder = base32.NewEncoding("abcdefghijkmnpqrstuvwxyz23456789").WithPadding(base32.NoPadding)
)

const (
	SecretTokenLength = 26
)

// generate a secret token that cannot be brute-forced via online attacks
func GenerateSecretToken() string {
	// 128 bits of entropy are enough to resist any online attack:
	var buf [16]byte
	rand.Read(buf[:])
	// 26 ASCII characters, should be fine for most purposes
	return b32encoder.EncodeToString(buf[:])
}

// securely check if a supplied token matches a stored token
func SecretTokensMatch(storedToken string, suppliedToken string) bool {
	// XXX fix a potential gotcha: if the stored token is uninitialized,
	// then nothing should match it, not even supplying an empty token.
	if len(storedToken) == 0 {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(storedToken), []byte(suppliedToken)) == 1
}
