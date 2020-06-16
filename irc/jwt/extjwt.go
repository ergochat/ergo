// Copyright (c) 2020 Daniel Oaks <daniel@danieloaks.net>
// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	ErrNoKeys = errors.New("No signing keys are enabled")
)

type MapClaims jwt.MapClaims

type JwtServiceConfig struct {
	Expiration        time.Duration
	Secret            string
	secretBytes       []byte
	RSAPrivateKeyFile string `yaml:"rsa-private-key-file"`
	rsaPrivateKey     *rsa.PrivateKey
}

func (t *JwtServiceConfig) Postprocess() (err error) {
	t.secretBytes = []byte(t.Secret)
	t.Secret = ""
	if t.RSAPrivateKeyFile != "" {
		keyBytes, err := ioutil.ReadFile(t.RSAPrivateKeyFile)
		if err != nil {
			return err
		}
		d, _ := pem.Decode(keyBytes)
		if err != nil {
			return err
		}
		t.rsaPrivateKey, err = x509.ParsePKCS1PrivateKey(d.Bytes)
		if err != nil {
			privateKey, err := x509.ParsePKCS8PrivateKey(d.Bytes)
			if err != nil {
				return err
			}
			if rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey); ok {
				t.rsaPrivateKey = rsaPrivateKey
			} else {
				return fmt.Errorf("Non-RSA key type for extjwt: %T", privateKey)
			}
		}
	}
	return nil
}

func (t *JwtServiceConfig) Enabled() bool {
	return t.Expiration != 0 && (len(t.secretBytes) != 0 || t.rsaPrivateKey != nil)
}

func (t *JwtServiceConfig) Sign(claims MapClaims) (result string, err error) {
	claims["exp"] = time.Now().Unix() + int64(t.Expiration/time.Second)

	if t.rsaPrivateKey != nil {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
		return token.SignedString(t.rsaPrivateKey)
	} else if len(t.secretBytes) != 0 {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
		return token.SignedString(t.secretBytes)
	} else {
		return "", ErrNoKeys
	}
}
