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

func TestCertfpComparisons(t *testing.T) {
	opensslFP := "3D:6B:11:BF:B4:05:C3:F8:4B:38:CD:30:38:FB:EC:01:71:D5:03:54:79:04:07:88:4C:A5:5D:23:41:85:66:C9"
	oragonoFP := "3d6b11bfb405c3f84b38cd3038fbec0171d50354790407884ca55d23418566c9"
	badFP := "3d6b11bfb405c3f84b38cd3038fbec0171d50354790407884ca55d23418566c"
	badFP2 := "*"

	normalizedOpenssl, err := NormalizeCertfp(opensslFP)
	assertEqual(err, nil, t)
	assertEqual(normalizedOpenssl, oragonoFP, t)

	normalizedOragono, err := NormalizeCertfp(oragonoFP)
	assertEqual(err, nil, t)
	assertEqual(normalizedOragono, oragonoFP, t)

	_, err = NormalizeCertfp(badFP)
	if err == nil {
		t.Errorf("corrupt fp should fail normalization")
	}
	_, err = NormalizeCertfp(badFP2)
	if err == nil {
		t.Errorf("corrupt fp should fail normalization")
	}
}
