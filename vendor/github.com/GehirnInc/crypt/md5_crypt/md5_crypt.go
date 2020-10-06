// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package md5_crypt implements the standard Unix MD5-crypt algorithm created by
// Poul-Henning Kamp for FreeBSD.
package md5_crypt

import (
	"bytes"
	"crypto/md5"
	"crypto/subtle"

	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/common"
	"github.com/GehirnInc/crypt/internal"
)

func init() {
	crypt.RegisterCrypt(crypt.MD5, New, MagicPrefix)
}

// NOTE: Cisco IOS only allows salts of length 4.

const (
	MagicPrefix   = "$1$"
	SaltLenMin    = 1 // Real minimum is 0, but that isn't useful.
	SaltLenMax    = 8
	RoundsDefault = 1000
)

type crypter struct{ Salt common.Salt }

// New returns a new crypt.Crypter computing the MD5-crypt password hashing.
func New() crypt.Crypter {
	return &crypter{
		common.Salt{
			MagicPrefix:   []byte(MagicPrefix),
			SaltLenMin:    SaltLenMin,
			SaltLenMax:    SaltLenMax,
			RoundsDefault: RoundsDefault,
		},
	}
}

func (c *crypter) Generate(key, salt []byte) (result string, err error) {
	if len(salt) == 0 {
		salt = c.Salt.Generate(SaltLenMax)
	}
	salt, _, _, _, err = c.Salt.Decode(salt)
	if err != nil {
		return
	}

	keyLen := len(key)
	h := md5.New()

	// Compute sumB
	h.Write(key)
	h.Write(salt)
	h.Write(key)
	sumB := h.Sum(nil)

	// Compute sumA
	h.Reset()
	h.Write(key)
	h.Write(c.Salt.MagicPrefix)
	h.Write(salt)
	h.Write(internal.RepeatByteSequence(sumB, keyLen))
	// The original implementation now does something weird:
	//   For every 1 bit in the key, the first 0 is added to the buffer
	//   For every 0 bit, the first character of the key
	// This does not seem to be what was intended but we have to follow this to
	// be compatible.
	for i := keyLen; i > 0; i >>= 1 {
		if i%2 == 0 {
			h.Write(key[0:1])
		} else {
			h.Write([]byte{0})
		}
	}
	sumA := h.Sum(nil)
	internal.CleanSensitiveData(sumB)

	// In fear of password crackers here comes a quite long loop which just
	// processes the output of the previous round again.
	// We cannot ignore this here.
	for i := 0; i < RoundsDefault; i++ {
		h.Reset()

		// Add key or last result.
		if i%2 != 0 {
			h.Write(key)
		} else {
			h.Write(sumA)
		}
		// Add salt for numbers not divisible by 3.
		if i%3 != 0 {
			h.Write(salt)
		}
		// Add key for numbers not divisible by 7.
		if i%7 != 0 {
			h.Write(key)
		}
		// Add key or last result.
		if i&1 != 0 {
			h.Write(sumA)
		} else {
			h.Write(key)
		}
		copy(sumA, h.Sum(nil))
	}

	buf := bytes.Buffer{}
	buf.Grow(len(c.Salt.MagicPrefix) + len(salt) + 1 + 22)
	buf.Write(c.Salt.MagicPrefix)
	buf.Write(salt)
	buf.WriteByte('$')
	buf.Write(common.Base64_24Bit([]byte{
		sumA[12], sumA[6], sumA[0],
		sumA[13], sumA[7], sumA[1],
		sumA[14], sumA[8], sumA[2],
		sumA[15], sumA[9], sumA[3],
		sumA[5], sumA[10], sumA[4],
		sumA[11],
	}))
	return buf.String(), nil
}

func (c *crypter) Verify(hashedKey string, key []byte) error {
	newHash, err := c.Generate(key, []byte(hashedKey))
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(newHash), []byte(hashedKey)) != 1 {
		return crypt.ErrKeyMismatch
	}
	return nil
}

func (c *crypter) Cost(hashedKey string) (int, error) { return RoundsDefault, nil }

func (c *crypter) SetSalt(salt common.Salt) { c.Salt = salt }
