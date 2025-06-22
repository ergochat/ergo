package irc

import "testing"

func TestKeyCheck(t *testing.T) {
	cases := []struct {
		input  string
		isEvil bool
	}{
		{"ImNormalButIHaveCaps", true},
		{"imnormalandidonthavecaps", false},
		{"ergo.chat/vendor-extension", false},
		{"", true},
		{":imevil", true},
		{"im:evil", true},
		{"key£with$not%allowed^chars", true},
		{"key.thats_completely/normal-and.fine", false},
	}

	for _, c := range cases {
		if metadataKeyIsEvil(c.input) != c.isEvil {
			t.Errorf("%s should have returned %v. but it didn't. so that's not great", c.input, c.isEvil)
		}
	}
}
