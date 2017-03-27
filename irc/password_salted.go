// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"crypto/rand"

	"golang.org/x/crypto/bcrypt"
)

const newSaltLen = 30
const defaultPasswordCost = 14

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

// PasswordManager supports the hashing and comparing of passwords with the given salt.
type PasswordManager struct {
	salt []byte
}

// NewPasswordManager returns a new PasswordManager with the given salt.
func NewPasswordManager(salt []byte) PasswordManager {
	var pwm PasswordManager
	pwm.salt = salt
	return pwm
}

// assemblePassword returns an assembled slice of bytes for the given password details.
func (pwm *PasswordManager) assemblePassword(specialSalt []byte, password string) []byte {
	var assembledPasswordBytes []byte
	assembledPasswordBytes = append(assembledPasswordBytes, pwm.salt...)
	assembledPasswordBytes = append(assembledPasswordBytes, '-')
	assembledPasswordBytes = append(assembledPasswordBytes, specialSalt...)
	assembledPasswordBytes = append(assembledPasswordBytes, '-')
	assembledPasswordBytes = append(assembledPasswordBytes, []byte(password)...)
	return assembledPasswordBytes
}

// GenerateFromPassword encrypts the given password.
func (pwm *PasswordManager) GenerateFromPassword(specialSalt []byte, password string) ([]byte, error) {
	assembledPasswordBytes := pwm.assemblePassword(specialSalt, password)
	return bcrypt.GenerateFromPassword(assembledPasswordBytes, defaultPasswordCost)
}

// CompareHashAndPassword compares a hashed password with its possible plaintext equivalent.
// Returns nil on success, or an error on failure.
func (pwm *PasswordManager) CompareHashAndPassword(hashedPassword []byte, specialSalt []byte, password string) error {
	assembledPasswordBytes := pwm.assemblePassword(specialSalt, password)
	return bcrypt.CompareHashAndPassword(hashedPassword, assembledPasswordBytes)
}
