package jwt

import (
	"testing"
	"time"
)

func TestAuthTokenRoundTrip(t *testing.T) {
	conf := AuthTokensConfig{
		Enabled: true,
		Services: map[string]JwtServiceConfig{
			"FILEHOST": {
				Expiration: 10 * time.Minute,
				URL:        "https://example.com",
				Algorithm:  "rsa",
				KeyString:  rsaTestPrivKey,
			},
		},
	}

	err := conf.Postprocess()
	if err != nil {
		t.Fatalf("couldn't parse config: %v", err)
	}

	tok := AuthToken{
		ServerName:  "irc.ergo.chat",
		Service:     "FILEHOST",
		AccountName: "slingamn",
		Scope:       "#ergo",
		ChannelMode: "o",
	}

	jtok, err := conf.Issue(tok)
	if err != nil {
		t.Fatalf("couldn't issue token: %v", err)
	}

	result, err := conf.Verify("FILEHOST", "https://example.com", jtok)
	if err != nil {
		t.Errorf("couldn't validate token: %v", err)
	}

	if result.AccountName != "slingamn" || result.Scope != "#ergo" {
		t.Errorf("didn't recover required fields from token: %#v", result)
	}

	_, err = conf.Verify("FILEHOST", "https://example.com", jtok[:len(jtok)-1])
	if err == nil {
		t.Errorf("validated token with bad signature")
	}
}
