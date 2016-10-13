// Copyright (c) 2012-2014 Jeremy Latt
// released under the MIT license

package irc

import (
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrEmptyPassword means that an empty password was given.
	ErrEmptyPassword = errors.New("empty password")
)

// GenerateEncodedPassword returns an encrypted password, encoded into a string with base64.
func GenerateEncodedPassword(passwd string) (encoded string, err error) {
	if passwd == "" {
		err = ErrEmptyPassword
		return
	}
	bcrypted, err := bcrypt.GenerateFromPassword([]byte(passwd), bcrypt.MinCost)
	if err != nil {
		return
	}
	encoded = base64.StdEncoding.EncodeToString(bcrypted)
	return
}

// DecodePasswordHash takes a base64-encoded password hash and returns the appropriate bytes.
func DecodePasswordHash(encoded string) (decoded []byte, err error) {
	if encoded == "" {
		err = ErrEmptyPassword
		return
	}
	decoded, err = base64.StdEncoding.DecodeString(encoded)
	return
}

// ComparePassword compares a given password with the given hash.
func ComparePassword(hash, password []byte) error {
	return bcrypt.CompareHashAndPassword(hash, password)
}
