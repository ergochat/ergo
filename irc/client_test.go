// Copyright (c) 2019 Shivaram Lingamneni
// released under the MIT license

package irc

import (
	"testing"
)

func TestGenerateBatchID(t *testing.T) {
	var session Session
	s := make(StringSet)

	count := 100000
	for i := 0; i < count; i++ {
		s.Add(session.generateBatchID())
	}

	if len(s) != count {
		t.Error("duplicate batch ID detected")
	}
}

func BenchmarkGenerateBatchID(b *testing.B) {
	var session Session
	for i := 0; i < b.N; i++ {
		session.generateBatchID()
	}
}
