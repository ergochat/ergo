// Copyright (c) 2012-2014 Jeremy Latt
// released under the MIT license

package irc

import (
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

var (
	EmptyPasswordError = errors.New("empty password")
)

func GenerateEncodedPassword(passwd string) (encoded string, err error) {
	if passwd == "" {
		err = EmptyPasswordError
		return
	}
	bcrypted, err := bcrypt.GenerateFromPassword([]byte(passwd), bcrypt.MinCost)
	if err != nil {
		return
	}
	encoded = base64.StdEncoding.EncodeToString(bcrypted)
	return
}

func DecodePassword(encoded string) (decoded []byte, err error) {
	if encoded == "" {
		err = EmptyPasswordError
		return
	}
	decoded, err = base64.StdEncoding.DecodeString(encoded)
	return
}

func ComparePassword(hash, password []byte) error {
	return bcrypt.CompareHashAndPassword(hash, password)
}
