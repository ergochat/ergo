// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package mkcerts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// CreateCertBytes creates a testing ECDSA certificate, returning the cert and key bytes.
func CreateCertBytes(orgName string, host string) (certBytes []byte, keyBytes []byte, err error) {
	validFrom := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := validFrom.Add(validFor)

	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{orgName},
		},
		NotBefore: validFrom,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// TODO: allow explicitly listing allowed addresses/names
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("::1"))
	if host != "" {
		template.DNSNames = append(template.DNSNames, host)
	}
	template.DNSNames = append(template.DNSNames, "localhost")

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create certificate: %s", err.Error())
	}

	certBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to marshal ECDSA private key: %v", err.Error())
	}
	pemBlock := pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	keyBytes = pem.EncodeToMemory(&pemBlock)
	return certBytes, keyBytes, nil
}

// CreateCert creates a testing ECDSA certificate, outputting the cert and key at the given filenames.
func CreateCert(orgName string, host string, certFilename string, keyFilename string) error {
	certBytes, keyBytes, err := CreateCertBytes(orgName, host)

	if err != nil {
		return err
	}

	certOut, err := os.Create(certFilename)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", certFilename, err.Error())
	}
	defer certOut.Close()
	_, err = certOut.Write(certBytes)
	if err != nil {
		return fmt.Errorf("failed to write out cert file %s: %s", certFilename, err.Error())
	}

	keyOut, err := os.OpenFile(keyFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", keyFilename, err.Error())
	}
	defer keyOut.Close()
	_, err = keyOut.Write(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to write out key file %s: %s", keyFilename, err.Error())
	}

	return nil
}
