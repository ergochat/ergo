// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package email

import (
	"errors"
	dkim "github.com/toorop/go-dkim"
	"io/ioutil"
)

var (
	ErrMissingFields = errors.New("DKIM config is missing fields")
)

type DKIMConfig struct {
	Domain   string
	Selector string
	KeyFile  string `yaml:"key-file"`
	keyBytes []byte
}

func (dkim *DKIMConfig) Postprocess() (err error) {
	if dkim.Domain != "" {
		if dkim.Selector == "" || dkim.KeyFile == "" {
			return ErrMissingFields
		}
		dkim.keyBytes, err = ioutil.ReadFile(dkim.KeyFile)
		if err != nil {
			return err
		}
	}
	return nil
}

var defaultOptions = dkim.SigOptions{
	Version:               1,
	Canonicalization:      "relaxed/relaxed",
	Algo:                  "rsa-sha256",
	Headers:               []string{"from", "to", "subject", "message-id", "date"},
	BodyLength:            0,
	QueryMethods:          []string{"dns/txt"},
	AddSignatureTimestamp: true,
	SignatureExpireIn:     0,
}

func DKIMSign(message []byte, dkimConfig DKIMConfig) (result []byte, err error) {
	options := defaultOptions
	options.PrivateKey = dkimConfig.keyBytes
	options.Domain = dkimConfig.Domain
	options.Selector = dkimConfig.Selector
	err = dkim.Sign(&message, options)
	return message, err
}
