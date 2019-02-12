// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import (
	"testing"
)

const (
	storedToken = "1e82d113a59a874cccf82063ec603221"
	badToken    = "1e82d113a59a874cccf82063ec603222"
	shortToken  = "1e82d113a59a874cccf82063ec60322"
	longToken   = "1e82d113a59a874cccf82063ec6032211"
)

func TestGenerateSecretToken(t *testing.T) {
	token := GenerateSecretToken()
	if len(token) != SecretTokenLength {
		t.Errorf("bad token: %v", token)
	}
}

func TestTokenCompare(t *testing.T) {
	if !SecretTokensMatch(storedToken, storedToken) {
		t.Error("matching tokens must match")
	}

	if SecretTokensMatch(storedToken, badToken) {
		t.Error("non-matching tokens must not match")
	}

	if SecretTokensMatch(storedToken, shortToken) {
		t.Error("non-matching tokens must not match")
	}

	if SecretTokensMatch(storedToken, longToken) {
		t.Error("non-matching tokens must not match")
	}

	if SecretTokensMatch("", "") {
		t.Error("the empty token should not match anything")
	}

	if SecretTokensMatch("", storedToken) {
		t.Error("the empty token should not match anything")
	}
}

func BenchmarkGenerateSecretToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateSecretToken()
	}
}
