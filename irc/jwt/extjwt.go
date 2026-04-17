// Copyright (c) 2020 Daniel Oaks <daniel@danieloaks.net>
// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package jwt

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

var (
	ErrNoKeys = errors.New("No EXTJWT signing keys are enabled")
)

type MapClaims jwt.MapClaims

type JwtServiceConfig struct {
	Expiration    time.Duration
	Description   string
	URL           string `yaml:"url"`
	Algorithm     string `yaml:"algorithm"`
	KeyString     string `yaml:"key"`
	KeyFile       string `yaml:"key-file"`
	signingMethod jwt.SigningMethod
	signingKey    any
	verifyKey     any
}

func (t *JwtServiceConfig) Postprocess() (err error) {
	if t.Algorithm == "" {
		// disabled
		return
	}

	var keyBytes []byte
	if t.KeyFile != "" {
		keyBytes, err = os.ReadFile(t.KeyFile)
		if err != nil {
			return
		}
	} else if t.KeyString != "" {
		keyBytes = []byte(t.KeyString)
	} else {
		return ErrNoKeys
	}

	switch strings.ToLower(t.Algorithm) {
	case "hmac":
		t.signingKey = keyBytes
		t.verifyKey = keyBytes
		t.signingMethod = jwt.SigningMethodHS256
	case "rsa":
		rsaPrivkey, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
		if err != nil {
			return err
		}
		t.signingKey = rsaPrivkey
		t.verifyKey = rsaPrivkey.Public()
		t.signingMethod = jwt.SigningMethodRS256
	case "eddsa":
		ecPrivkey, err := jwt.ParseEdPrivateKeyFromPEM(keyBytes)
		if err != nil {
			return err
		}
		t.signingKey = ecPrivkey
		ed25519PrivKey, ok := ecPrivkey.(ed25519.PrivateKey)
		if !ok {
			// impossible due to golang-jwt enforcement:
			return errors.New("unexpected non-ed25519 private key found")
		}
		t.verifyKey = ed25519PrivKey.Public()
		t.signingMethod = jwt.SigningMethodEdDSA
	default:
		return fmt.Errorf("invalid JWT algorithm: %s", t.Algorithm)
	}

	return nil
}

func (t *JwtServiceConfig) Enabled() bool {
	return t.Expiration != 0 && t.signingMethod != nil
}

func (t *JwtServiceConfig) SignEXTJWT(claims MapClaims) (result string, err error) {
	if !t.Enabled() {
		err = ErrNoKeys
		return
	}

	claims["exp"] = time.Now().Unix() + int64(t.Expiration/time.Second)

	token := jwt.NewWithClaims(t.signingMethod, jwt.MapClaims(claims))
	return token.SignedString(t.signingKey)
}
