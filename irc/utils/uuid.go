// Copyright (c) 2022 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

var (
	ErrInvalidUUID = errors.New("Invalid uuid")
)

// Technically a UUIDv4 has version bits set, but this doesn't matter in practice
type UUID [16]byte

func (u UUID) MarshalJSON() (b []byte, err error) {
	b = make([]byte, 24)
	b[0] = '"'
	base64.RawURLEncoding.Encode(b[1:], u[:])
	b[23] = '"'
	return
}

func (u *UUID) UnmarshalJSON(b []byte) (err error) {
	if len(b) != 24 {
		return ErrInvalidUUID
	}
	readLen, err := base64.RawURLEncoding.Decode(u[:], b[1:23])
	if readLen != 16 {
		return ErrInvalidUUID
	}
	return nil
}

func (u *UUID) String() string {
	return base64.RawURLEncoding.EncodeToString(u[:])
}

func GenerateUUIDv4() (result UUID) {
	_, err := rand.Read(result[:])
	if err != nil {
		panic(err)
	}
	return
}

func DecodeUUID(ustr string) (result UUID, err error) {
	length, err := base64.RawURLEncoding.Decode(result[:], []byte(ustr))
	if err == nil && length != 16 {
		err = ErrInvalidUUID
	}
	return
}
