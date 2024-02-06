package oauth2

/*
https://github.com/emersion/go-sasl/blob/e73c9f7bad438a9bf3f5b28e661b74d752ecafdd/oauthbearer.go

Copyright 2019-2022 Simon Ser, Frode Aannevik, Max Mazurov
Released under the MIT license
*/

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	ErrUnexpectedClientResponse = errors.New("unexpected client response")
)

// The OAUTHBEARER mechanism name.
const OAuthBearer = "OAUTHBEARER"

type OAuthBearerError struct {
	Status  string `json:"status"`
	Schemes string `json:"schemes"`
	Scope   string `json:"scope"`
}

type OAuthBearerOptions struct {
	Username string `json:"username,omitempty"`
	Token    string `json:"token,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
}

func (err *OAuthBearerError) Error() string {
	return fmt.Sprintf("OAUTHBEARER authentication error (%v)", err.Status)
}

type OAuthBearerAuthenticator func(opts OAuthBearerOptions) *OAuthBearerError

type OAuthBearerServer struct {
	done         bool
	failErr      error
	authenticate OAuthBearerAuthenticator
}

func (a *OAuthBearerServer) fail(descr string) ([]byte, bool, error) {
	blob, err := json.Marshal(OAuthBearerError{
		Status:  "invalid_request",
		Schemes: "bearer",
	})
	if err != nil {
		panic(err) // wtf
	}
	a.failErr = errors.New(descr)
	return blob, false, nil
}

func (a *OAuthBearerServer) Next(response []byte) (challenge []byte, done bool, err error) {
	// Per RFC, we cannot just send an error, we need to return JSON-structured
	// value as a challenge and then after getting dummy response from the
	// client stop the exchange.
	if a.failErr != nil {
		// Server libraries (go-smtp, go-imap) will not call Next on
		// protocol-specific SASL cancel response ('*'). However, GS2 (and
		// indirectly OAUTHBEARER) defines a protocol-independent way to do so
		// using 0x01.
		if len(response) != 1 && response[0] != 0x01 {
			return nil, true, errors.New("unexpected response")
		}
		return nil, true, a.failErr
	}

	if a.done {
		err = ErrUnexpectedClientResponse
		return
	}

	// Generate empty challenge.
	if response == nil {
		return []byte{}, false, nil
	}

	a.done = true

	// Cut n,a=username,\x01host=...\x01auth=...
	// into
	//   n
	//   a=username
	//   \x01host=...\x01auth=...\x01\x01
	parts := bytes.SplitN(response, []byte{','}, 3)
	if len(parts) != 3 {
		return a.fail("Invalid response")
	}
	flag := parts[0]
	authzid := parts[1]
	if !bytes.Equal(flag, []byte{'n'}) {
		return a.fail("Invalid response, missing 'n' in gs2-cb-flag")
	}
	opts := OAuthBearerOptions{}
	if len(authzid) > 0 {
		if !bytes.HasPrefix(authzid, []byte("a=")) {
			return a.fail("Invalid response, missing 'a=' in gs2-authzid")
		}
		opts.Username = string(bytes.TrimPrefix(authzid, []byte("a=")))
	}

	// Cut \x01host=...\x01auth=...\x01\x01
	// into
	//   *empty*
	//   host=...
	//   auth=...
	//   *empty*
	//
	// Note that this code does not do a lot of checks to make sure the input
	// follows the exact format specified by RFC.
	params := bytes.Split(parts[2], []byte{0x01})
	for _, p := range params {
		// Skip empty fields (one at start and end).
		if len(p) == 0 {
			continue
		}

		pParts := bytes.SplitN(p, []byte{'='}, 2)
		if len(pParts) != 2 {
			return a.fail("Invalid response, missing '='")
		}

		switch string(pParts[0]) {
		case "host":
			opts.Host = string(pParts[1])
		case "port":
			port, err := strconv.ParseUint(string(pParts[1]), 10, 16)
			if err != nil {
				return a.fail("Invalid response, malformed 'port' value")
			}
			opts.Port = int(port)
		case "auth":
			const prefix = "bearer "
			strValue := string(pParts[1])
			// Token type is case-insensitive.
			if !strings.HasPrefix(strings.ToLower(strValue), prefix) {
				return a.fail("Unsupported token type")
			}
			opts.Token = strValue[len(prefix):]
		default:
			return a.fail("Invalid response, unknown parameter: " + string(pParts[0]))
		}
	}

	authzErr := a.authenticate(opts)
	if authzErr != nil {
		blob, err := json.Marshal(authzErr)
		if err != nil {
			panic(err) // wtf
		}
		a.failErr = authzErr
		return blob, false, nil
	}

	return nil, true, nil
}

func NewOAuthBearerServer(auth OAuthBearerAuthenticator) *OAuthBearerServer {
	return &OAuthBearerServer{
		authenticate: auth,
	}
}
