// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package email

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"os"

	dkim "github.com/emersion/go-msgauth/dkim"
)

var (
	ErrMissingFields = errors.New("DKIM config is missing fields")
)

type DKIMConfig struct {
	Domain   string
	Selector string
	KeyFile  string `yaml:"key-file"`
	privKey  crypto.Signer
}

func (dkim *DKIMConfig) Enabled() bool {
	return dkim.Domain != ""
}

func (dkim *DKIMConfig) Postprocess() (err error) {
	if !dkim.Enabled() {
		return nil
	}

	if dkim.Selector == "" || dkim.KeyFile == "" {
		return ErrMissingFields
	}

	keyBytes, err := os.ReadFile(dkim.KeyFile)
	if err != nil {
		return fmt.Errorf("Could not read DKIM key file: %w", err)
	}
	dkim.privKey, err = parseDKIMPrivKey(keyBytes)
	if err != nil {
		return fmt.Errorf("Could not parse DKIM key file: %w", err)
	}

	return nil
}

func parseDKIMPrivKey(input []byte) (crypto.Signer, error) {
	if len(input) == 0 {
		return nil, errors.New("DKIM private key is empty")
	}

	// raw ed25519 private key format
	if len(input) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(input), nil
	}

	d, _ := pem.Decode(input)
	if d == nil {
		return nil, errors.New("Invalid PEM data for DKIM private key")
	}

	if rsaKey, err := x509.ParsePKCS1PrivateKey(d.Bytes); err == nil {
		return rsaKey, nil
	}

	if k, err := x509.ParsePKCS8PrivateKey(d.Bytes); err == nil {
		switch key := k.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case ed25519.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("Unacceptable type for DKIM private key: %T", k)
		}
	}

	return nil, errors.New("No acceptable format for DKIM private key")
}

func DKIMSign(message []byte, dkimConfig DKIMConfig) (result []byte, err error) {
	options := dkim.SignOptions{
		Domain:                 dkimConfig.Domain,
		Selector:               dkimConfig.Selector,
		Signer:                 dkimConfig.privKey,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
	}
	input := bytes.NewBuffer(message)
	output := bytes.NewBuffer(make([]byte, 0, len(message)+1024))
	err = dkim.Sign(output, input, &options)
	return output.Bytes(), err
}
