// Copyright (c) 2024 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package jwt

import (
	"fmt"
	"io"
	"os"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
)

var (
	ErrAuthDisabled        = fmt.Errorf("JWT authentication is disabled")
	ErrNoValidAccountClaim = fmt.Errorf("JWT token did not contain an acceptable account name claim")
)

// JWTAuthConfig is the config for Ergo to accept JWTs via draft/bearer
type JWTAuthConfig struct {
	Enabled    bool                 `yaml:"enabled"`
	Autocreate bool                 `yaml:"autocreate"`
	Tokens     []JWTAuthTokenConfig `yaml:"tokens"`
}

type JWTAuthTokenConfig struct {
	Algorithm     string `yaml:"algorithm"`
	KeyString     string `yaml:"key"`
	KeyFile       string `yaml:"key-file"`
	key           any
	parser        *jwt.Parser
	AccountClaims []string `yaml:"account-claims"`
	StripDomain   string   `yaml:"strip-domain"`
}

func (j *JWTAuthConfig) Postprocess() error {
	if !j.Enabled {
		return nil
	}

	if len(j.Tokens) == 0 {
		return fmt.Errorf("JWT authentication enabled, but no valid tokens defined")
	}

	for i := range j.Tokens {
		if err := j.Tokens[i].Postprocess(); err != nil {
			return err
		}
	}

	return nil
}

func (j *JWTAuthTokenConfig) Postprocess() error {
	keyBytes, err := j.keyBytes()
	if err != nil {
		return err
	}

	j.Algorithm = strings.ToLower(j.Algorithm)

	var methods []string
	switch j.Algorithm {
	case "hmac":
		j.key = keyBytes
		methods = []string{"HS256", "HS384", "HS512"}
	case "rsa":
		rsaKey, err := jwt.ParseRSAPublicKeyFromPEM(keyBytes)
		if err != nil {
			return err
		}
		j.key = rsaKey
		methods = []string{"RS256", "RS384", "RS512"}
	case "eddsa":
		eddsaKey, err := jwt.ParseEdPublicKeyFromPEM(keyBytes)
		if err != nil {
			return err
		}
		j.key = eddsaKey
		methods = []string{"EdDSA"}
	default:
		return fmt.Errorf("invalid jwt algorithm: %s", j.Algorithm)
	}
	j.parser = jwt.NewParser(jwt.WithValidMethods(methods))

	if len(j.AccountClaims) == 0 {
		return fmt.Errorf("JWT auth enabled, but no account-claims specified")
	}

	j.StripDomain = strings.ToLower(j.StripDomain)
	return nil
}

func (j *JWTAuthConfig) Validate(t string) (accountName string, err error) {
	if !j.Enabled || len(j.Tokens) == 0 {
		return "", ErrAuthDisabled
	}

	for i := range j.Tokens {
		accountName, err = j.Tokens[i].Validate(t)
		if err == nil {
			return
		}
	}
	return
}

func (j *JWTAuthTokenConfig) keyBytes() (result []byte, err error) {
	if j.KeyFile != "" {
		o, err := os.Open(j.KeyFile)
		if err != nil {
			return nil, err
		}
		return io.ReadAll(o)
	}
	if j.KeyString != "" {
		return []byte(j.KeyString), nil
	}
	return nil, fmt.Errorf("JWT auth enabled, but no JWT key specified")
}

// implements jwt.Keyfunc
func (j *JWTAuthTokenConfig) keyFunc(_ *jwt.Token) (interface{}, error) {
	return j.key, nil
}

func (j *JWTAuthTokenConfig) Validate(t string) (accountName string, err error) {
	token, err := j.parser.Parse(t, j.keyFunc)
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		// impossible with Parse (as opposed to ParseWithClaims)
		return "", fmt.Errorf("unexpected type from parsed token claims: %T", claims)
	}

	for _, c := range j.AccountClaims {
		if v, ok := claims[c]; ok {
			if vstr, ok := v.(string); ok {
				// validate and strip email addresses:
				if idx := strings.IndexByte(vstr, '@'); idx != -1 {
					suffix := vstr[idx+1:]
					vstr = vstr[:idx]
					if strings.ToLower(suffix) != j.StripDomain {
						continue
					}
				}
				return vstr, nil // success
			}
		}
	}

	return "", ErrNoValidAccountClaim
}
