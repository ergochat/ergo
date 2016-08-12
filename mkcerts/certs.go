// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
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

// CreateCert creates a testing ECDSA certificate, outputting the cert and key at the given filenames.
func CreateCert(orgName string, host string, certFilename string, keyFilename string) error {
	validFrom := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := validFrom.Add(validFor)

	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %s", err)
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
		return fmt.Errorf("Failed to create certificate: %s", err.Error())
	}

	certOut, err := os.Create(certFilename)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", certFilename, err.Error())
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.OpenFile(keyFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", keyFilename, err.Error())
	}
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("Unable to marshal ECDSA private key: %v", err.Error())
	}
	pemBlock := pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	pem.Encode(keyOut, &pemBlock)
	keyOut.Close()
	return nil
}
