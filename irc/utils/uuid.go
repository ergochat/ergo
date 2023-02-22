// Copyright (c) 2022 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

type ErrInvalidUUID struct {
	invalid []byte
}

func (e ErrInvalidUUID) Error() string {
	return fmt.Sprintf("Invalid uuid:%q", string(e.invalid))
}

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
		return ErrInvalidUUID{b}
	}
	readLen, err := base64.RawURLEncoding.Decode(u[:], b[1:23])
	if err != nil {
		return err
	}
	if readLen != 16 {
		return ErrInvalidUUID{b}
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
	if err != nil {
		return
	}
	if length != 16 {
		err = ErrInvalidUUID{[]byte(ustr)}
		return
	}
	return
}
