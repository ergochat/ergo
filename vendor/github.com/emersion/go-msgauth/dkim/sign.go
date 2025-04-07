package dkim

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ed25519"
)

var randReader io.Reader = rand.Reader

// SignOptions is used to configure Sign. Domain, Selector and Signer are
// mandatory.
type SignOptions struct {
	// The SDID claiming responsibility for an introduction of a message into the
	// mail stream. Hence, the SDID value is used to form the query for the public
	// key. The SDID MUST correspond to a valid DNS name under which the DKIM key
	// record is published.
	//
	// This can't be empty.
	Domain string
	// The selector subdividing the namespace for the domain.
	//
	// This can't be empty.
	Selector string
	// The Agent or User Identifier (AUID) on behalf of which the SDID is taking
	// responsibility.
	//
	// This is optional.
	Identifier string

	// The key used to sign the message.
	//
	// Supported Signer.Public() values are *rsa.PublicKey and
	// ed25519.PublicKey.
	Signer crypto.Signer
	// The hash algorithm used to sign the message. If zero, a default hash will
	// be chosen.
	//
	// The only supported hash algorithm is crypto.SHA256.
	Hash crypto.Hash

	// Header and body canonicalization algorithms.
	//
	// If empty, CanonicalizationSimple is used.
	HeaderCanonicalization Canonicalization
	BodyCanonicalization   Canonicalization

	// A list of header fields to include in the signature. If nil, all headers
	// will be included. If not nil, "From" MUST be in the list.
	//
	// See RFC 6376 section 5.4.1 for recommended header fields.
	HeaderKeys []string

	// The expiration time. A zero value means no expiration.
	Expiration time.Time

	// A list of query methods used to retrieve the public key.
	//
	// If nil, it is implicitly defined as QueryMethodDNSTXT.
	QueryMethods []QueryMethod
}

// Signer generates a DKIM signature.
//
// The whole message header and body must be written to the Signer. Close should
// always be called (either after the whole message has been written, or after
// an error occurred and the signer won't be used anymore). Close may return an
// error in case signing fails.
//
// After a successful Close, Signature can be called to retrieve the
// DKIM-Signature header field that the caller should prepend to the message.
type Signer struct {
	pw        *io.PipeWriter
	done      <-chan error
	sigParams map[string]string // only valid after done received nil
}

// NewSigner creates a new signer. It returns an error if SignOptions is
// invalid.
func NewSigner(options *SignOptions) (*Signer, error) {
	if options == nil {
		return nil, fmt.Errorf("dkim: no options specified")
	}
	if options.Domain == "" {
		return nil, fmt.Errorf("dkim: no domain specified")
	}
	if options.Selector == "" {
		return nil, fmt.Errorf("dkim: no selector specified")
	}
	if options.Signer == nil {
		return nil, fmt.Errorf("dkim: no signer specified")
	}

	headerCan := options.HeaderCanonicalization
	if headerCan == "" {
		headerCan = CanonicalizationSimple
	}
	if _, ok := canonicalizers[headerCan]; !ok {
		return nil, fmt.Errorf("dkim: unknown header canonicalization %q", headerCan)
	}

	bodyCan := options.BodyCanonicalization
	if bodyCan == "" {
		bodyCan = CanonicalizationSimple
	}
	if _, ok := canonicalizers[bodyCan]; !ok {
		return nil, fmt.Errorf("dkim: unknown body canonicalization %q", bodyCan)
	}

	var keyAlgo string
	switch options.Signer.Public().(type) {
	case *rsa.PublicKey:
		keyAlgo = "rsa"
	case ed25519.PublicKey:
		keyAlgo = "ed25519"
	default:
		return nil, fmt.Errorf("dkim: unsupported key algorithm %T", options.Signer.Public())
	}

	hash := options.Hash
	var hashAlgo string
	switch options.Hash {
	case 0: // sha256 is the default
		hash = crypto.SHA256
		fallthrough
	case crypto.SHA256:
		hashAlgo = "sha256"
	case crypto.SHA1:
		return nil, fmt.Errorf("dkim: hash algorithm too weak: sha1")
	default:
		return nil, fmt.Errorf("dkim: unsupported hash algorithm")
	}

	if options.HeaderKeys != nil {
		ok := false
		for _, k := range options.HeaderKeys {
			if strings.EqualFold(k, "From") {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("dkim: the From header field must be signed")
		}
	}

	done := make(chan error, 1)
	pr, pw := io.Pipe()

	s := &Signer{
		pw:   pw,
		done: done,
	}

	closeReadWithError := func(err error) {
		pr.CloseWithError(err)
		done <- err
	}

	go func() {
		defer close(done)

		// Read header
		br := bufio.NewReader(pr)
		h, err := readHeader(br)
		if err != nil {
			closeReadWithError(err)
			return
		}

		// Hash body
		hasher := hash.New()
		can := canonicalizers[bodyCan].CanonicalizeBody(hasher)
		if _, err := io.Copy(can, br); err != nil {
			closeReadWithError(err)
			return
		}
		if err := can.Close(); err != nil {
			closeReadWithError(err)
			return
		}
		bodyHashed := hasher.Sum(nil)

		params := map[string]string{
			"v":  "1",
			"a":  keyAlgo + "-" + hashAlgo,
			"bh": base64.StdEncoding.EncodeToString(bodyHashed),
			"c":  string(headerCan) + "/" + string(bodyCan),
			"d":  options.Domain,
			//"l": "", // TODO
			"s": options.Selector,
			"t": formatTime(now()),
			//"z": "", // TODO
		}

		var headerKeys []string
		if options.HeaderKeys != nil {
			headerKeys = options.HeaderKeys
		} else {
			for _, kv := range h {
				k, _ := parseHeaderField(kv)
				headerKeys = append(headerKeys, k)
			}
		}
		params["h"] = formatTagList(headerKeys)

		if options.Identifier != "" {
			params["i"] = options.Identifier
		}

		if options.QueryMethods != nil {
			methods := make([]string, len(options.QueryMethods))
			for i, method := range options.QueryMethods {
				methods[i] = string(method)
			}
			params["q"] = formatTagList(methods)
		}

		if !options.Expiration.IsZero() {
			params["x"] = formatTime(options.Expiration)
		}

		// Hash and sign headers
		hasher.Reset()
		picker := newHeaderPicker(h)
		for _, k := range headerKeys {
			kv := picker.Pick(k)
			if kv == "" {
				// The Signer MAY include more instances of a header field name
				// in "h=" than there are actual corresponding header fields so
				// that the signature will not verify if additional header
				// fields of that name are added.
				continue
			}

			kv = canonicalizers[headerCan].CanonicalizeHeader(kv)
			if _, err := io.WriteString(hasher, kv); err != nil {
				closeReadWithError(err)
				return
			}
		}

		params["b"] = ""
		sigField := formatSignature(params)
		sigField = canonicalizers[headerCan].CanonicalizeHeader(sigField)
		sigField = strings.TrimRight(sigField, crlf)
		if _, err := io.WriteString(hasher, sigField); err != nil {
			closeReadWithError(err)
			return
		}
		hashed := hasher.Sum(nil)

		// Don't pass Hash to Sign for ed25519 as it doesn't support it
		// and will return an error ("ed25519: cannot sign hashed message").
		if keyAlgo == "ed25519" {
			hash = crypto.Hash(0)
		}

		sig, err := options.Signer.Sign(randReader, hashed, hash)
		if err != nil {
			closeReadWithError(err)
			return
		}
		params["b"] = base64.StdEncoding.EncodeToString(sig)

		s.sigParams = params
		closeReadWithError(nil)
	}()

	return s, nil
}

// Write implements io.WriteCloser.
func (s *Signer) Write(b []byte) (n int, err error) {
	return s.pw.Write(b)
}

// Close implements io.WriteCloser. The error return by Close must be checked.
func (s *Signer) Close() error {
	if err := s.pw.Close(); err != nil {
		return err
	}
	return <-s.done
}

// Signature returns the whole DKIM-Signature header field. It can only be
// called after a successful Signer.Close call.
//
// The returned value contains both the header field name, its value and the
// final CRLF.
func (s *Signer) Signature() string {
	if s.sigParams == nil {
		panic("dkim: Signer.Signature must only be called after a succesful Signer.Close")
	}
	return formatSignature(s.sigParams)
}

// Sign signs a message. It reads it from r and writes the signed version to w.
func Sign(w io.Writer, r io.Reader, options *SignOptions) error {
	s, err := NewSigner(options)
	if err != nil {
		return err
	}
	defer s.Close()

	// We need to keep the message in a buffer so we can write the new DKIM
	// header field before the rest of the message
	var b bytes.Buffer
	mw := io.MultiWriter(&b, s)

	if _, err := io.Copy(mw, r); err != nil {
		return err
	}
	if err := s.Close(); err != nil {
		return err
	}

	if _, err := io.WriteString(w, s.Signature()); err != nil {
		return err
	}
	_, err = io.Copy(w, &b)
	return err
}

func formatSignature(params map[string]string) string {
	sig := formatHeaderParams(headerFieldName, params)
	return sig
}

func formatTagList(l []string) string {
	return strings.Join(l, ":")
}

func formatTime(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}
