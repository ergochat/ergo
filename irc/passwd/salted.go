// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package passwd

import (
	"crypto/rand"

	"golang.org/x/crypto/bcrypt"
)

const (
	// newSaltLen is how many bytes long newly-generated salts are.
	newSaltLen = 30
	// defaultPasswordCost is the bcrypt cost we use for passwords.
	defaultPasswordCost = 14
)

// NewSalt returns a salt for crypto uses.
func NewSalt() ([]byte, error) {
	salt := make([]byte, newSaltLen)
	_, err := rand.Read(salt)

	if err != nil {
		var emptySalt []byte
		return emptySalt, err
	}

	return salt, nil
}

// SaltedManager supports the hashing and comparing of passwords with the given salt.
type SaltedManager struct {
	salt []byte
}

// NewSaltedManager returns a new SaltedManager with the given salt.
func NewSaltedManager(salt []byte) SaltedManager {
	var sm SaltedManager
	sm.salt = salt
	return sm
}

// assemblePassword returns an assembled slice of bytes for the given password details.
func (sm *SaltedManager) assemblePassword(specialSalt []byte, password string) []byte {
	var assembledPasswordBytes []byte
	assembledPasswordBytes = append(assembledPasswordBytes, sm.salt...)
	assembledPasswordBytes = append(assembledPasswordBytes, '-')
	assembledPasswordBytes = append(assembledPasswordBytes, specialSalt...)
	assembledPasswordBytes = append(assembledPasswordBytes, '-')
	assembledPasswordBytes = append(assembledPasswordBytes, []byte(password)...)
	return assembledPasswordBytes
}

// GenerateFromPassword encrypts the given password.
func (sm *SaltedManager) GenerateFromPassword(specialSalt []byte, password string) ([]byte, error) {
	assembledPasswordBytes := sm.assemblePassword(specialSalt, password)
	return bcrypt.GenerateFromPassword(assembledPasswordBytes, defaultPasswordCost)
}

// CompareHashAndPassword compares a hashed password with its possible plaintext equivalent.
// Returns nil on success, or an error on failure.
func (sm *SaltedManager) CompareHashAndPassword(hashedPassword []byte, specialSalt []byte, password string) error {
	assembledPasswordBytes := sm.assemblePassword(specialSalt, password)
	return bcrypt.CompareHashAndPassword(hashedPassword, assembledPasswordBytes)
}
