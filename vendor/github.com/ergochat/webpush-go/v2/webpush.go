package webpush

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

const MaxRecordSize uint32 = 4096

var (
	ErrRecordSizeTooSmall = errors.New("record size too small for message")

	invalidAuthKeyLength = errors.New("invalid auth key length (must be 16)")

	defaultHTTPClient HTTPClient = &http.Client{}
)

// HTTPClient is an interface for sending the notification HTTP request / testing
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Options are config and extra params needed to send a notification
type Options struct {
	HTTPClient      HTTPClient // Will replace with *http.Client by default if not included
	RecordSize      uint32     // Limit the record size
	Subscriber      string     // Sub in VAPID JWT token
	Topic           string     // Set the Topic header to collapse a pending messages (Optional)
	TTL             int        // Set the TTL on the endpoint POST request, in seconds
	Urgency         Urgency    // Set the Urgency header to change a message priority (Optional)
	VAPIDKeys       *VAPIDKeys // VAPID public-private keypair to generate the VAPID Authorization header
	VapidExpiration time.Time  // optional expiration for VAPID JWT token (defaults to now + 12 hours)
}

// Keys represents a subscription's keys (its ECDH public key on the P-256 curve
// and its 16-byte authentication secret).
type Keys struct {
	Auth   [16]byte
	P256dh *ecdh.PublicKey
}

// Equal compares two Keys for equality.
func (k *Keys) Equal(o Keys) bool {
	return k.Auth == o.Auth && k.P256dh.Equal(o.P256dh)
}

var _ json.Marshaler = (*Keys)(nil)
var _ json.Unmarshaler = (*Keys)(nil)

type marshaledKeys struct {
	Auth   string `json:"auth"`
	P256dh string `json:"p256dh"`
}

// MarshalJSON implements json.Marshaler, allowing serialization to JSON.
func (k *Keys) MarshalJSON() ([]byte, error) {
	m := marshaledKeys{
		Auth:   base64.RawStdEncoding.EncodeToString(k.Auth[:]),
		P256dh: base64.RawStdEncoding.EncodeToString(k.P256dh.Bytes()),
	}
	return json.Marshal(&m)
}

// MarshalJSON implements json.Unmarshaler, allowing deserialization from JSON.
func (k *Keys) UnmarshalJSON(b []byte) (err error) {
	var m marshaledKeys
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	authBytes, err := decodeSubscriptionKey(m.Auth)
	if err != nil {
		return err
	}
	if len(authBytes) != 16 {
		return fmt.Errorf("invalid auth bytes length %d (must be 16)", len(authBytes))
	}
	copy(k.Auth[:], authBytes)
	rawDHKey, err := decodeSubscriptionKey(m.P256dh)
	if err != nil {
		return err
	}
	k.P256dh, err = ecdh.P256().NewPublicKey(rawDHKey)
	return err
}

// DecodeSubscriptionKeys decodes and validates a base64-encoded pair of subscription keys
// (the authentication secret and ECDH public key).
func DecodeSubscriptionKeys(auth, p256dh string) (keys Keys, err error) {
	authBytes, err := decodeSubscriptionKey(auth)
	if err != nil {
		return
	}
	if len(authBytes) != 16 {
		err = invalidAuthKeyLength
		return
	}
	copy(keys.Auth[:], authBytes)
	dhBytes, err := decodeSubscriptionKey(p256dh)
	if err != nil {
		return
	}
	keys.P256dh, err = ecdh.P256().NewPublicKey(dhBytes)
	if err != nil {
		return
	}
	return
}

// Subscription represents a PushSubscription object from the Push API
type Subscription struct {
	Endpoint string `json:"endpoint"`
	Keys     Keys   `json:"keys"`
}

// SendNotification sends a push notification to a subscription's endpoint,
// applying encryption (RFC 8291) and adding a VAPID header (RFC 8292).
func SendNotification(ctx context.Context, message []byte, s *Subscription, options *Options) (*http.Response, error) {
	// Compose message body (RFC8291 encryption of the message)
	body, err := EncryptNotification(message, s.Keys, options.RecordSize)
	if err != nil {
		return nil, err
	}

	// Get VAPID Authorization header
	vapidAuthHeader, err := getVAPIDAuthorizationHeader(
		s.Endpoint,
		options.Subscriber,
		options.VAPIDKeys,
		options.VapidExpiration,
	)
	if err != nil {
		return nil, err
	}

	// Compose and send the HTTP request
	return sendNotification(ctx, s.Endpoint, options, vapidAuthHeader, body)
}

// EncryptNotification implements the encryption algorithm specified by RFC 8291 for web push
// (RFC 8188's aes128gcm content-encoding, with the key material derived from
// elliptic curve Diffie-Hellman over the P-256 curve).
func EncryptNotification(message []byte, keys Keys, recordSize uint32) ([]byte, error) {
	// Get the record size
	if recordSize == 0 {
		recordSize = MaxRecordSize
	} else if recordSize < 128 {
		return nil, ErrRecordSizeTooSmall
	}

	// Allocate buffer to hold the eventual message
	// [ header block ] [ ciphertext ] [ 16 byte AEAD tag ], totaling RecordSize bytes
	// the ciphertext is the encryption of: [ message ] [ \x02 ] [ 0 or more \x00 as needed ]
	recordBuf := make([]byte, recordSize)
	// remainingBuf tracks our current writing position in recordBuf:
	remainingBuf := recordBuf

	// Application server key pairs (single use)
	localPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	localPublicKey := localPrivateKey.PublicKey()

	// Encryption Content-Coding Header
	// +-----------+--------+-----------+---------------+
	// | salt (16) | rs (4) | idlen (1) | keyid (idlen) |
	// +-----------+--------+-----------+---------------+
	// in our case the keyid is localPublicKey.Bytes(), so 65 bytes
	// First, generate the salt
	_, err = rand.Read(remainingBuf[:16])
	if err != nil {
		return nil, err
	}
	salt := remainingBuf[:16]
	remainingBuf = remainingBuf[16:]
	binary.BigEndian.PutUint32(remainingBuf[:], recordSize)
	remainingBuf = remainingBuf[4:]
	localPublicKeyBytes := localPublicKey.Bytes()
	remainingBuf[0] = byte(len(localPublicKeyBytes))
	remainingBuf = remainingBuf[1:]
	copy(remainingBuf[:], localPublicKeyBytes)
	remainingBuf = remainingBuf[len(localPublicKeyBytes):]

	// Combine application keys with receiver's EC public key to derive ECDH shared secret
	sharedECDHSecret, err := localPrivateKey.ECDH(keys.P256dh)
	if err != nil {
		return nil, fmt.Errorf("deriving shared secret: %w", err)
	}

	// ikm
	prkInfoBuf := bytes.NewBuffer([]byte("WebPush: info\x00"))
	prkInfoBuf.Write(keys.P256dh.Bytes())
	prkInfoBuf.Write(localPublicKey.Bytes())

	prkHKDF := hkdf.New(sha256.New, sharedECDHSecret, keys.Auth[:], prkInfoBuf.Bytes())
	ikm, err := getHKDFKey(prkHKDF, 32)
	if err != nil {
		return nil, err
	}

	// Derive Content Encryption Key
	contentEncryptionKeyInfo := []byte("Content-Encoding: aes128gcm\x00")
	contentHKDF := hkdf.New(sha256.New, ikm, salt, contentEncryptionKeyInfo)
	contentEncryptionKey, err := getHKDFKey(contentHKDF, 16)
	if err != nil {
		return nil, err
	}

	// Derive the Nonce
	nonceInfo := []byte("Content-Encoding: nonce\x00")
	nonceHKDF := hkdf.New(sha256.New, ikm, salt, nonceInfo)
	nonce, err := getHKDFKey(nonceHKDF, 12)
	if err != nil {
		return nil, err
	}

	// Cipher
	c, err := aes.NewCipher(contentEncryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// need 1 byte for the 0x02 delimiter, 16 bytes for the AEAD tag
	if len(remainingBuf) < len(message)+17 {
		return nil, ErrRecordSizeTooSmall
	}
	// Copy the message plaintext into the buffer
	copy(remainingBuf[:], message[:])
	// The plaintext to be encrypted will include the padding delimiter and the padding;
	// cut off the final 16 bytes that are reserved for the AEAD tag
	plaintext := remainingBuf[:len(remainingBuf)-16]
	remainingBuf = remainingBuf[len(message):]
	// Add padding delimiter
	remainingBuf[0] = '\x02'
	remainingBuf = remainingBuf[1:]
	// The rest of the buffer is already zero-padded

	// Encipher the plaintext in place, then add the AEAD tag at the end.
	// "To reuse plaintext's storage for the encrypted output, use plaintext[:0]
	// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext."
	gcm.Seal(plaintext[:0], nonce, plaintext, nil)

	return recordBuf, nil
}

func sendNotification(ctx context.Context, endpoint string, options *Options, vapidAuthHeader string, body []byte) (*http.Response, error) {
	// POST request
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	if ctx != nil {
		req = req.WithContext(ctx)
	}

	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("TTL", strconv.Itoa(options.TTL))

	// Сheck the optional headers
	if len(options.Topic) > 0 {
		req.Header.Set("Topic", options.Topic)
	}

	if isValidUrgency(options.Urgency) {
		req.Header.Set("Urgency", string(options.Urgency))
	}

	req.Header.Set("Authorization", vapidAuthHeader)

	// Send the request
	var client HTTPClient
	if options.HTTPClient != nil {
		client = options.HTTPClient
	} else {
		client = defaultHTTPClient
	}

	return client.Do(req)
}

// decodeSubscriptionKey decodes a base64 subscription key.
func decodeSubscriptionKey(key string) ([]byte, error) {
	key = strings.TrimRight(key, "=")

	if strings.IndexByte(key, '+') != -1 || strings.IndexByte(key, '/') != -1 {
		return base64.RawStdEncoding.DecodeString(key)
	}
	return base64.RawURLEncoding.DecodeString(key)
}

// Returns a key of length "length" given an hkdf function
func getHKDFKey(hkdf io.Reader, length int) ([]byte, error) {
	key := make([]byte, length)
	n, err := io.ReadFull(hkdf, key)
	if n != len(key) || err != nil {
		return key, err
	}

	return key, nil
}
