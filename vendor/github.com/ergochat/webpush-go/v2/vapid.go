package webpush

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// VAPIDKeys is a public-private keypair for use in VAPID.
// It marshals to a JSON string containing the PEM of the PKCS8
// of the private key.
type VAPIDKeys struct {
	privateKey *ecdsa.PrivateKey
	publicKey  string // raw bytes encoding in urlsafe base64, as per RFC
}

// PublicKeyString returns the base64url-encoded uncompressed public key of the keypair,
// as defined in RFC8292.
func (v *VAPIDKeys) PublicKeyString() string {
	return v.publicKey
}

// PrivateKey returns the private key of the keypair.
func (v *VAPIDKeys) PrivateKey() *ecdsa.PrivateKey {
	return v.privateKey
}

// Equal compares two VAPIDKeys for equality.
func (v *VAPIDKeys) Equal(o *VAPIDKeys) bool {
	return v.privateKey.Equal(o.privateKey)
}

var _ json.Marshaler = (*VAPIDKeys)(nil)
var _ json.Unmarshaler = (*VAPIDKeys)(nil)

// MarshalJSON implements json.Marshaler, allowing serialization to JSON.
func (v *VAPIDKeys) MarshalJSON() ([]byte, error) {
	pkcs8bytes, err := x509.MarshalPKCS8PrivateKey(v.privateKey)
	if err != nil {
		return nil, err
	}
	pemBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8bytes,
	}
	pemBytes := pem.EncodeToMemory(&pemBlock)
	if pemBytes == nil {
		return nil, fmt.Errorf("could not encode VAPID keys as PEM")
	}
	return json.Marshal(string(pemBytes))
}

// MarshalJSON implements json.Unmarshaler, allowing deserialization from JSON.
func (v *VAPIDKeys) UnmarshalJSON(b []byte) error {
	var pemKey string
	if err := json.Unmarshal(b, &pemKey); err != nil {
		return err
	}
	pemBlock, _ := pem.Decode([]byte(pemKey))
	if pemBlock == nil {
		return fmt.Errorf("could not decode PEM block with VAPID keys")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return err
	}
	privateKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("Invalid type of private key %T", privateKey)
	}
	if privateKey.Curve != elliptic.P256() {
		return fmt.Errorf("Invalid curve for private key %v", privateKey.Curve)
	}
	publicKeyStr, err := makePublicKeyString(privateKey)
	if err != nil {
		return err // should not be possible since we confirmed P256 already
	}

	// success
	v.privateKey = privateKey
	v.publicKey = publicKeyStr
	return nil
}

// GenerateVAPIDKeys generates a VAPID keypair (an ECDSA keypair on
// the P-256 curve).
func GenerateVAPIDKeys() (result *VAPIDKeys, err error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}

	pubKeyECDH, err := private.PublicKey.ECDH()
	if err != nil {
		return
	}
	publicKey := base64.RawURLEncoding.EncodeToString(pubKeyECDH.Bytes())

	return &VAPIDKeys{
		privateKey: private,
		publicKey:  publicKey,
	}, nil
}

// ECDSAToVAPIDKeys wraps an existing ecdsa.PrivateKey in VAPIDKeys for use in
// VAPID header signing.
func ECDSAToVAPIDKeys(privKey *ecdsa.PrivateKey) (result *VAPIDKeys, err error) {
	if privKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("Invalid curve for private key %v", privKey.Curve)
	}
	publicKeyString, err := makePublicKeyString(privKey)
	if err != nil {
		return nil, err
	}
	return &VAPIDKeys{
		privateKey: privKey,
		publicKey:  publicKeyString,
	}, nil
}

func makePublicKeyString(privKey *ecdsa.PrivateKey) (result string, err error) {
	// to get the raw bytes we have to convert the public key to *ecdh.PublicKey
	// this type assertion (from the crypto.PublicKey returned by (*ecdsa.PrivateKey).Public()
	// to *ecdsa.PublicKey) cannot fail:
	publicKey, err := privKey.Public().(*ecdsa.PublicKey).ECDH()
	if err != nil {
		return // should not be possible if we confirmed P256 already
	}
	return base64.RawURLEncoding.EncodeToString(publicKey.Bytes()), nil
}

// getVAPIDAuthorizationHeader
func getVAPIDAuthorizationHeader(
	endpoint string,
	subscriber string,
	vapidKeys *VAPIDKeys,
	expiration time.Time,
) (string, error) {
	if expiration.IsZero() {
		expiration = time.Now().Add(time.Hour * 12)
	}

	// Create the JWT token
	subURL, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}

	// Unless subscriber is an HTTPS URL, assume an e-mail address
	if !strings.HasPrefix(subscriber, "https:") && !strings.HasPrefix(subscriber, "mailto:") {
		subscriber = "mailto:" + subscriber
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"aud": subURL.Scheme + "://" + subURL.Host,
		"exp": expiration.Unix(),
		"sub": subscriber,
	})

	// Sign token with private key
	jwtString, err := token.SignedString(vapidKeys.privateKey)
	if err != nil {
		return "", err
	}

	return "vapid t=" + jwtString + ", k=" + vapidKeys.publicKey, nil
}
