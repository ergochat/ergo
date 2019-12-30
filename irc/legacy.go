// Copyright (c) 2018 Shivaram Lingamneni

package irc

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/tidwall/buntdb"
	"golang.org/x/crypto/bcrypt"
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

// helper to check a version 0 password hash, with global and per-passphrase salts
func checkLegacyPasswordV0(hashedPassword, globalSalt, passphraseSalt []byte, passphrase string) error {
	var assembledPasswordBytes []byte
	assembledPasswordBytes = append(assembledPasswordBytes, globalSalt...)
	assembledPasswordBytes = append(assembledPasswordBytes, '-')
	assembledPasswordBytes = append(assembledPasswordBytes, passphraseSalt...)
	assembledPasswordBytes = append(assembledPasswordBytes, '-')
	assembledPasswordBytes = append(assembledPasswordBytes, []byte(passphrase)...)
	return bcrypt.CompareHashAndPassword(hashedPassword, assembledPasswordBytes)
}

// checks a version 0 password hash; if successful, upgrades the database entry to version 1
func handleLegacyPasswordV0(server *Server, account string, credentials AccountCredentials, passphrase string) (err error) {
	var globalSaltString string
	err = server.store.View(func(tx *buntdb.Tx) (err error) {
		globalSaltString, err = tx.Get("crypto.salt")
		return err
	})
	if err != nil {
		return err
	}
	globalSalt, err := base64.StdEncoding.DecodeString(globalSaltString)
	if err != nil {
		return err
	}

	err = checkLegacyPasswordV0(credentials.PassphraseHash, globalSalt, credentials.PassphraseSalt, passphrase)
	if err != nil {
		// invalid password
		return err
	}

	// upgrade credentials
	err = server.accounts.setPassword(account, passphrase, true)
	if err != nil {
		server.logger.Error("internal", fmt.Sprintf("could not upgrade user password: %v", err))
	}

	return nil
}
