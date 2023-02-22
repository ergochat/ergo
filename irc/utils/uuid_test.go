package utils

import "testing"

func TestErrInvalidUUID(t *testing.T) {
	bad := []byte("abcd")
	want := `Invalid uuid:"abcd"`
	got := ErrInvalidUUID{bad}.Error()
	if want != got {
		t.Fatalf("want:%q got:%q", want, got)
	}
}
