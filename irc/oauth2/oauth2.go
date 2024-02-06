// Copyright 2022-2023 Simon Ser <contact@emersion.fr>
// Derived from https://git.sr.ht/~emersion/soju/tree/36d6cb19a4f90d217d55afb0b15318321baaad09/item/auth/oauth2.go
// Originally released under the AGPLv3, relicensed to the Ergo project under the MIT license
// Modifications copyright 2024 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// Released under the MIT license

package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrAuthDisabled = fmt.Errorf("OAuth 2.0 authentication is disabled")

	// all cases where the infrastructure is working correctly, but we determined
	// that the user supplied an invalid token
	ErrInvalidToken = fmt.Errorf("OAuth 2.0 bearer token invalid")
)

type OAuth2BearerConfig struct {
	Enabled              bool          `yaml:"enabled"`
	Autocreate           bool          `yaml:"autocreate"`
	AuthScript           bool          `yaml:"auth-script"`
	IntrospectionURL     string        `yaml:"introspection-url"`
	IntrospectionTimeout time.Duration `yaml:"introspection-timeout"`
	// omit for `none`, required for `client_secret_basic`
	ClientID     string `yaml:"client-id"`
	ClientSecret string `yaml:"client-secret"`
}

func (o *OAuth2BearerConfig) Postprocess() error {
	if !o.Enabled {
		return nil
	}

	if o.IntrospectionTimeout == 0 {
		return fmt.Errorf("a nonzero oauthbearer introspection timeout is required (try 10s)")
	}

	if _, err := url.Parse(o.IntrospectionURL); err != nil {
		return fmt.Errorf("invalid introspection-url: %w", err)
	}

	return nil
}

func (o *OAuth2BearerConfig) Introspect(ctx context.Context, token string) (username string, err error) {
	if !o.Enabled {
		return "", ErrAuthDisabled
	}

	ctx, cancel := context.WithTimeout(ctx, o.IntrospectionTimeout)
	defer cancel()

	reqValues := make(url.Values)
	reqValues.Set("token", token)

	reqBody := strings.NewReader(reqValues.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.IntrospectionURL, reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to create OAuth 2.0 introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if o.ClientID != "" {
		req.SetBasicAuth(url.QueryEscape(o.ClientID), url.QueryEscape(o.ClientSecret))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send OAuth 2.0 introspection request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OAuth 2.0 introspection error: %v", resp.Status)
	}

	var data oauth2Introspection
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("failed to decode OAuth 2.0 introspection response: %v", err)
	}

	if !data.Active {
		return "", ErrInvalidToken
	}
	if data.Username == "" {
		// We really need the username here, otherwise an OAuth 2.0 user can
		// impersonate any other user.
		return "", fmt.Errorf("missing username in OAuth 2.0 introspection response")
	}

	return data.Username, nil
}

type oauth2Introspection struct {
	Active   bool   `json:"active"`
	Username string `json:"username"`
}
