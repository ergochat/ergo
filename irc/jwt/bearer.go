// Copyright (c) 2024 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package jwt

import (
	"fmt"
	"os"
	"strings"

	"github.com/ergochat/ergo/irc/utils"
	jwt "github.com/golang-jwt/jwt/v5"
)

var (
	ErrAuthDisabled        = fmt.Errorf("JWT authentication is disabled")
	ErrNoValidAccountClaim = fmt.Errorf("JWT token did not contain an acceptable account name claim")
	ErrNoValidAudClaim     = fmt.Errorf("JWT token did not contain an acceptable aud claim")
)

// JWTAuthConfig is the config for Ergo to accept JWTs via draft/bearer
type JWTAuthConfig struct {
	Enabled    bool                   `yaml:"enabled"`
	Autocreate bool                   `yaml:"autocreate"`
	Tokens     []JWTBearerTokenConfig `yaml:"tokens"`
}

type JWTBearerTokenConfig struct {
	Algorithm     string `yaml:"algorithm"`
	KeyString     string `yaml:"key"`
	KeyFile       string `yaml:"key-file"`
	key           any
	parser        *jwt.Parser
	AccountClaims []string `yaml:"account-claims"`
	StripDomain   string   `yaml:"strip-domain"`
	ValidateAud   []string `yaml:"validate-aud"`
	allowedAuds   utils.HashSet[string]
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

func (j *JWTBearerTokenConfig) Postprocess() error {
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
	j.parser = jwt.NewParser(jwt.WithValidMethods(methods), jwt.WithExpirationRequired())

	if len(j.AccountClaims) == 0 {
		return fmt.Errorf("JWT auth enabled, but no account-claims specified")
	}

	j.StripDomain = strings.ToLower(j.StripDomain)

	if len(j.ValidateAud) != 0 {
		j.allowedAuds = utils.SetLiteral(j.ValidateAud...)
	}

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

func (j *JWTBearerTokenConfig) keyBytes() (result []byte, err error) {
	if j.KeyFile != "" {
		return os.ReadFile(j.KeyFile)
	}
	if j.KeyString != "" {
		return []byte(j.KeyString), nil
	}
	return nil, fmt.Errorf("JWT auth enabled, but no JWT key specified")
}

// implements jwt.Keyfunc
func (j *JWTBearerTokenConfig) keyFunc(_ *jwt.Token) (interface{}, error) {
	return j.key, nil
}

func (j *JWTBearerTokenConfig) Validate(t string) (accountName string, err error) {
	token, err := j.parser.Parse(t, j.keyFunc)
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		// impossible with Parse (as opposed to ParseWithClaims)
		return "", fmt.Errorf("unexpected type from parsed token claims: %T", claims)
	}

	if !j.validateAudClaim(claims) {
		return "", ErrNoValidAudClaim
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

func (j *JWTBearerTokenConfig) validateAudClaim(claims jwt.MapClaims) bool {
	if j.allowedAuds == nil {
		return true // no validate-aud means any aud is allowed
	}

	audClaim, ok := claims["aud"]
	if !ok {
		return false
	}

	switch aud := audClaim.(type) {
	case string:
		return j.allowedAuds.Has(aud)
	case []any:
		for _, a := range aud {
			if aStr, ok := a.(string); ok {
				if j.allowedAuds.Has(aStr) {
					return true
				}
			}
		}
		return false
	case []string:
		for _, a := range aud {
			if j.allowedAuds.Has(a) {
				return true
			}
		}
		return false
	default:
		return false
	}
}
