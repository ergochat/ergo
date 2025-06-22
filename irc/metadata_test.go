package irc

import "testing"

func TestKeyCheck(t *testing.T) {
	cases := []struct {
		input  string
		isEvil bool
	}{
		{"ImNormal", false},
		{"", true},
		{":imevil", true},
		{"key£with$not%allowed^chars", true},
		{"key.thats_completely/normal-and.fine", false},
	}

	for _, c := range cases {
		if metadataKeyIsEvil(c.input) != c.isEvil {
			t.Errorf("%s should have returned %v. but it didn't. so that's not great", c.input, c.isEvil)
		}
	}
}
