package webpush

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
)

// ecdhPublicKeyToECDSA converts an ECDH key to an ECDSA key.
// This is deprecated as per https://github.com/golang/go/issues/63963
// but we need to do it in order to parse the legacy private key format.
func ecdhPublicKeyToECDSA(key *ecdh.PublicKey) (*ecdsa.PublicKey, error) {
	rawKey := key.Bytes()
	switch key.Curve() {
	case ecdh.P256():
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(0).SetBytes(rawKey[1:33]),
			Y:     big.NewInt(0).SetBytes(rawKey[33:]),
		}, nil
	case ecdh.P384():
		return &ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     big.NewInt(0).SetBytes(rawKey[1:49]),
			Y:     big.NewInt(0).SetBytes(rawKey[49:]),
		}, nil
	case ecdh.P521():
		return &ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     big.NewInt(0).SetBytes(rawKey[1:67]),
			Y:     big.NewInt(0).SetBytes(rawKey[67:]),
		}, nil
	default:
		return nil, fmt.Errorf("cannot convert non-NIST *ecdh.PublicKey to *ecdsa.PublicKey")
	}
}

func ecdhPrivateKeyToECDSA(key *ecdh.PrivateKey) (*ecdsa.PrivateKey, error) {
	// see https://github.com/golang/go/issues/63963
	pubKey, err := ecdhPublicKeyToECDSA(key.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("converting PublicKey part of *ecdh.PrivateKey: %w", err)
	}
	return &ecdsa.PrivateKey{
		PublicKey: *pubKey,
		D:         big.NewInt(0).SetBytes(key.Bytes()),
	}, nil
}

// DecodeLegacyVAPIDPrivateKey decodes the legacy string private key format
// returned by GenerateVAPIDKeys in v1.
func DecodeLegacyVAPIDPrivateKey(key string) (*VAPIDKeys, error) {
	bytes, err := decodeSubscriptionKey(key)
	if err != nil {
		return nil, err
	}

	ecdhPrivKey, err := ecdh.P256().NewPrivateKey(bytes)
	if err != nil {
		return nil, err
	}

	ecdsaPrivKey, err := ecdhPrivateKeyToECDSA(ecdhPrivKey)
	if err != nil {
		return nil, err
	}

	publicKey := base64.RawURLEncoding.EncodeToString(ecdhPrivKey.PublicKey().Bytes())
	return &VAPIDKeys{
		privateKey: ecdsaPrivKey,
		publicKey:  publicKey,
	}, nil
}
