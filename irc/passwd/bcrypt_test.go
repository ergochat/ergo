// Copyright (c) 2018 Shivaram Lingamneni
// released under the MIT license

package passwd

import (
	"testing"
)

func TestBasic(t *testing.T) {
	hash, err := GenerateFromPassword([]byte("this is my passphrase"), DefaultCost)
	if err != nil || len(hash) != 60 {
		t.Errorf("bad password hash output: error %s, output %s, len %d", err, hash, len(hash))
	}

	if CompareHashAndPassword(hash, []byte("this is my passphrase")) != nil {
		t.Errorf("hash comparison failed unexpectedly")
	}

	if CompareHashAndPassword(hash, []byte("this is not my passphrase")) == nil {
		t.Errorf("hash comparison succeeded unexpectedly")
	}
}

func TestVector(t *testing.T) {
	// sanity check for persisted hashes
	if CompareHashAndPassword(
		[]byte("$2a$12$sJokyLJ5px3Nb51DEDhsQ.wh8nfwEYuMbVYrpqO5v9Ylyj0YyVWj."),
		[]byte("this is my passphrase"),
	) != nil {
		t.Errorf("hash comparison failed unexpectedly")
	}
}

func TestLongPassphrases(t *testing.T) {
	longPassphrase := make([]byte, 168)
	for i := range longPassphrase {
		longPassphrase[i] = 'a'
	}
	hash, err := GenerateFromPassword(longPassphrase, DefaultCost)
	if err != nil {
		t.Errorf("bad password hash output: error %s", err)
	}

	if CompareHashAndPassword(hash, longPassphrase) != nil {
		t.Errorf("hash comparison failed unexpectedly")
	}

	// change a byte of the passphrase beyond the normal 80-character
	// bcrypt truncation boundary:
	longPassphrase[150] = 'b'
	if CompareHashAndPassword(hash, longPassphrase) == nil {
		t.Errorf("hash comparison succeeded unexpectedly")
	}
}

// this could be useful for tuning the cost parameter on specific hardware
func BenchmarkComparisons(b *testing.B) {
	pass := []byte("passphrase for benchmarking")
	hash, err := GenerateFromPassword(pass, DefaultCost)
	if err != nil {
		b.Errorf("bad output")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompareHashAndPassword(hash, pass)
	}
}
