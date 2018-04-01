// Copyright (c) 2012-2014 Jeremy Latt
// released under the MIT license

package passwd

import (
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrEmptyPassword means that an empty password was given.
	ErrEmptyPassword = errors.New("empty password")
)

// GenerateEncodedPasswordBytes returns an encrypted password, returning the bytes directly.
func GenerateEncodedPasswordBytes(passwd string) (encoded []byte, err error) {
	if passwd == "" {
		err = ErrEmptyPassword
		return
	}
	encoded, err = bcrypt.GenerateFromPassword([]byte(passwd), bcrypt.MinCost)
	return
}

// GenerateEncodedPassword returns an encrypted password, encoded into a string with base64.
func GenerateEncodedPassword(passwd string) (encoded string, err error) {
	bcrypted, err := GenerateEncodedPasswordBytes(passwd)
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

// ComparePasswordString compares a given password string with the given hash.
func ComparePasswordString(hash []byte, password string) error {
	return ComparePassword(hash, []byte(password))
}
