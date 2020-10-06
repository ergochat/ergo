// Copyright (c) 2018 Shivaram Lingamneni

package irc

import (
	"encoding/base64"
	"errors"
)

var (
	errInvalidPasswordHash = errors.New("invalid password hash")
)

// Decode a hashed passphrase as it would appear in a config file,
// retaining compatibility with old versions of `oragono genpasswd`
// that used to apply a redundant layer of base64
func decodeLegacyPasswordHash(hash string) ([]byte, error) {
	// a correctly formatted bcrypt hash is 60 bytes of printable ASCII
	if len(hash) == 80 {
		// double-base64, remove the outer layer:
		return base64.StdEncoding.DecodeString(hash)
	} else if len(hash) == 60 {
		return []byte(hash), nil
	} else {
		return nil, errInvalidPasswordHash
	}
}
