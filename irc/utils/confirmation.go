// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// Deterministically generates a confirmation code for some destructive activity;
// `name` is typically the name of the identity being destroyed (a channel being
// unregistered, or the server being crashed) and `createdAt` means a different
// value is required each time.
func ConfirmationCode(name string, createdAt time.Time) (code string) {
	buf := make([]byte, len(name)+8)
	binary.BigEndian.PutUint64(buf, uint64(createdAt.UnixNano()))
	copy(buf[8:], name[:])
	out := sha256.Sum256(buf)
	return B32Encoder.EncodeToString(out[:3])
}
