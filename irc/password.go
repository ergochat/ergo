package irc

import (
	"code.google.com/p/go.crypto/bcrypt"
	"encoding/base64"
	"errors"
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
