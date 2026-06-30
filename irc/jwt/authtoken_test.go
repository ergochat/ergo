package jwt

import (
	"reflect"
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

	result, err := conf.Verify("FILEHOST", jtok)
	if err != nil {
		t.Errorf("couldn't validate token: %v", err)
	}

	if result.AccountName != "slingamn" || result.Scope != "#ergo" {
		t.Errorf("didn't recover required fields from token: %#v", result)
	}

	_, err = conf.Verify("FILEHOST", jtok[:len(jtok)-1])
	if err == nil {
		t.Errorf("validated token with bad signature")
	}
}

func TestAuthTokenDiff(t *testing.T) {
	oldConf := AuthTokensConfig{
		Enabled: true,
		Services: map[string]JwtServiceConfig{
			"FILEHOST": {
				Expiration: 10 * time.Minute,
				URL:        "https://example.com/filehost",
				Algorithm:  "rsa",
				KeyString:  rsaTestPrivKey,
			},
			"QDB": {
				Expiration: 10 * time.Minute,
				URL:        "https://example.com/qdb",
				Algorithm:  "hmac",
				KeyString:  "MbKjh6CTqLMPZV9XLYmACw",
			},
			"JITSI": {
				Expiration: 10 * time.Minute,
				URL:        "https://example.com/jitsi",
				Algorithm:  "hmac",
				KeyString:  "uaKzJTbuqjHlbGrvwku2kw",
			},
		},
	}

	err := oldConf.Postprocess()
	if err != nil {
		t.Fatalf("couldn't parse config: %v", err)
	}

	newConf := AuthTokensConfig{
		Enabled: true,
		Services: map[string]JwtServiceConfig{
			// change the filehost URL
			"FILEHOST": {
				Expiration: 10 * time.Minute,
				URL:        "https://filehost.com/filehost",
				Algorithm:  "rsa",
				KeyString:  rsaTestPrivKey,
			},
			// QDB is deleted
			// jitsi is at the same URL with a different key
			"JITSI": {
				Expiration: 10 * time.Minute,
				URL:        "https://example.com/jitsi",
				Algorithm:  "rsa",
				KeyString:  rsaTestPrivKey,
			},
		},
	}

	err = newConf.Postprocess()
	if err != nil {
		t.Fatalf("couldn't parse config: %v", err)
	}

	expectedDiff := [][]string{
		{"DEL", "QDB"},
		{"NEW", "FILEHOST", "https://filehost.com/filehost"},
	}
	diff := oldConf.GetDifference(newConf)
	if !reflect.DeepEqual(diff, expectedDiff) {
		t.Fatalf("incorrect diff: %#v", diff)
	}
}
