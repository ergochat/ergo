package dkim

import (
	"bufio"
	"crypto"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type permFailError string

func (err permFailError) Error() string {
	return "dkim: " + string(err)
}

// IsPermFail returns true if the error returned by Verify is a permanent
// failure. A permanent failure is for instance a missing required field or a
// malformed header.
func IsPermFail(err error) bool {
	_, ok := err.(permFailError)
	return ok
}

type tempFailError string

func (err tempFailError) Error() string {
	return "dkim: " + string(err)
}

// IsTempFail returns true if the error returned by Verify is a temporary
// failure.
func IsTempFail(err error) bool {
	_, ok := err.(tempFailError)
	return ok
}

type failError string

func (err failError) Error() string {
	return "dkim: " + string(err)
}

// isFail returns true if the error returned by Verify is a signature error.
func isFail(err error) bool {
	_, ok := err.(failError)
	return ok
}

// ErrTooManySignatures is returned by Verify when the message exceeds the
// maximum number of signatures.
var ErrTooManySignatures = errors.New("dkim: too many signatures")

var requiredTags = []string{"v", "a", "b", "bh", "d", "h", "s"}

// A Verification is produced by Verify when it checks if one signature is
// valid. If the signature is valid, Err is nil.
type Verification struct {
	// The SDID claiming responsibility for an introduction of a message into the
	// mail stream.
	Domain string
	// The Agent or User Identifier (AUID) on behalf of which the SDID is taking
	// responsibility.
	Identifier string

	// The list of signed header fields.
	HeaderKeys []string

	// The time that this signature was created. If unknown, it's set to zero.
	Time time.Time
	// The expiration time. If the signature doesn't expire, it's set to zero.
	Expiration time.Time

	// Err is nil if the signature is valid.
	Err error
}

type signature struct {
	i int
	v string
}

// VerifyOptions allows to customize the default signature verification
// behavior.
type VerifyOptions struct {
	// LookupTXT returns the DNS TXT records for the given domain name. If nil,
	// net.LookupTXT is used.
	LookupTXT func(domain string) ([]string, error)
	// MaxVerifications controls the maximum number of signature verifications
	// to perform. If more signatures are present, the first MaxVerifications
	// signatures are verified, the rest are ignored and ErrTooManySignatures
	// is returned. If zero, there is no maximum.
	MaxVerifications int
}

// Verify checks if a message's signatures are valid. It returns one
// verification per signature.
//
// There is no guarantee that the reader will be completely consumed.
func Verify(r io.Reader) ([]*Verification, error) {
	return VerifyWithOptions(r, nil)
}

// VerifyWithOptions performs the same task as Verify, but allows specifying
// verification options.
func VerifyWithOptions(r io.Reader, options *VerifyOptions) ([]*Verification, error) {
	// Read header
	bufr := bufio.NewReader(r)
	h, err := readHeader(bufr)
	if err != nil {
		return nil, err
	}

	// Scan header fields for signatures
	var signatures []*signature
	for i, kv := range h {
		k, v := parseHeaderField(kv)
		if strings.EqualFold(k, headerFieldName) {
			signatures = append(signatures, &signature{i, v})
		}
	}

	tooManySignatures := false
	if options != nil && options.MaxVerifications > 0 && len(signatures) > options.MaxVerifications {
		tooManySignatures = true
		signatures = signatures[:options.MaxVerifications]
	}

	var verifs []*Verification
	if len(signatures) == 1 {
		// If there is only one signature - just verify it.
		v, err := verify(h, bufr, h[signatures[0].i], signatures[0].v, options)
		if err != nil && !IsTempFail(err) && !IsPermFail(err) && !isFail(err) {
			return nil, err
		}
		v.Err = err
		verifs = []*Verification{v}
	} else {
		verifs, err = parallelVerify(bufr, h, signatures, options)
		if err != nil {
			return nil, err
		}
	}

	if tooManySignatures {
		return verifs, ErrTooManySignatures
	}
	return verifs, nil
}

func parallelVerify(r io.Reader, h header, signatures []*signature, options *VerifyOptions) ([]*Verification, error) {
	pipeWriters := make([]*io.PipeWriter, len(signatures))
	// We can't pass pipeWriter to io.MultiWriter directly,
	// we need a slice of io.Writer, but we also need *io.PipeWriter
	// to call Close on it.
	writers := make([]io.Writer, len(signatures))
	chans := make([]chan *Verification, len(signatures))

	for i, sig := range signatures {
		// Be careful with loop variables and goroutines.
		i, sig := i, sig

		chans[i] = make(chan *Verification, 1)

		pr, pw := io.Pipe()
		writers[i] = pw
		pipeWriters[i] = pw

		go func() {
			v, err := verify(h, pr, h[sig.i], sig.v, options)

			// Make sure we consume the whole reader, otherwise io.Copy on
			// other side can block forever.
			io.Copy(ioutil.Discard, pr)

			v.Err = err
			chans[i] <- v
		}()
	}

	if _, err := io.Copy(io.MultiWriter(writers...), r); err != nil {
		return nil, err
	}
	for _, wr := range pipeWriters {
		wr.Close()
	}

	verifications := make([]*Verification, len(signatures))
	for i, ch := range chans {
		verifications[i] = <-ch
	}

	// Return unexpected failures as a separate error.
	for _, v := range verifications {
		err := v.Err
		if err != nil && !IsTempFail(err) && !IsPermFail(err) && !isFail(err) {
			v.Err = nil
			return verifications, err
		}
	}
	return verifications, nil
}

func verify(h header, r io.Reader, sigField, sigValue string, options *VerifyOptions) (*Verification, error) {
	verif := new(Verification)

	params, err := parseHeaderParams(sigValue)
	if err != nil {
		return verif, permFailError("malformed signature tags: " + err.Error())
	}

	if params["v"] != "1" {
		return verif, permFailError("incompatible signature version")
	}

	verif.Domain = stripWhitespace(params["d"])

	for _, tag := range requiredTags {
		if _, ok := params[tag]; !ok {
			return verif, permFailError("signature missing required tag")
		}
	}

	if i, ok := params["i"]; ok {
		verif.Identifier = stripWhitespace(i)
		if !strings.HasSuffix(verif.Identifier, "@"+verif.Domain) && !strings.HasSuffix(verif.Identifier, "."+verif.Domain) {
			return verif, permFailError("domain mismatch")
		}
	} else {
		verif.Identifier = "@" + verif.Domain
	}

	headerKeys := parseTagList(params["h"])
	ok := false
	for _, k := range headerKeys {
		if strings.EqualFold(k, "from") {
			ok = true
			break
		}
	}
	if !ok {
		return verif, permFailError("From field not signed")
	}
	verif.HeaderKeys = headerKeys

	if timeStr, ok := params["t"]; ok {
		t, err := parseTime(timeStr)
		if err != nil {
			return verif, permFailError("malformed time: " + err.Error())
		}
		verif.Time = t
	}
	if expiresStr, ok := params["x"]; ok {
		t, err := parseTime(expiresStr)
		if err != nil {
			return verif, permFailError("malformed expiration time: " + err.Error())
		}
		verif.Expiration = t
		if now().After(t) {
			return verif, permFailError("signature has expired")
		}
	}

	// Query public key
	// TODO: compute hash in parallel
	methods := []string{string(QueryMethodDNSTXT)}
	if methodsStr, ok := params["q"]; ok {
		methods = parseTagList(methodsStr)
	}
	var res *queryResult
	for _, method := range methods {
		if query, ok := queryMethods[QueryMethod(method)]; ok {
			if options != nil {
				res, err = query(verif.Domain, stripWhitespace(params["s"]), options.LookupTXT)
			} else {
				res, err = query(verif.Domain, stripWhitespace(params["s"]), nil)
			}
			break
		}
	}
	if err != nil {
		return verif, err
	} else if res == nil {
		return verif, permFailError("unsupported public key query method")
	}

	// Parse algos
	keyAlgo, hashAlgo, ok := strings.Cut(stripWhitespace(params["a"]), "-")
	if !ok {
		return verif, permFailError("malformed algorithm name")
	}

	// Check hash algo
	if res.HashAlgos != nil {
		ok := false
		for _, algo := range res.HashAlgos {
			if algo == hashAlgo {
				ok = true
				break
			}
		}
		if !ok {
			return verif, permFailError("inappropriate hash algorithm")
		}
	}
	var hash crypto.Hash
	switch hashAlgo {
	case "sha1":
		// RFC 8301 section 3.1: rsa-sha1 MUST NOT be used for signing or
		// verifying.
		return verif, permFailError(fmt.Sprintf("hash algorithm too weak: %v", hashAlgo))
	case "sha256":
		hash = crypto.SHA256
	default:
		return verif, permFailError("unsupported hash algorithm")
	}

	// Check key algo
	if res.KeyAlgo != keyAlgo {
		return verif, permFailError("inappropriate key algorithm")
	}

	if res.Services != nil {
		ok := false
		for _, s := range res.Services {
			if s == "email" {
				ok = true
				break
			}
		}
		if !ok {
			return verif, permFailError("inappropriate service")
		}
	}

	headerCan, bodyCan := parseCanonicalization(params["c"])
	if _, ok := canonicalizers[headerCan]; !ok {
		return verif, permFailError("unsupported header canonicalization algorithm")
	}
	if _, ok := canonicalizers[bodyCan]; !ok {
		return verif, permFailError("unsupported body canonicalization algorithm")
	}

	// The body length "l" parameter is insecure, because it allows parts of
	// the message body to not be signed. Reject messages which have it set.
	if _, ok := params["l"]; ok {
		// TODO: technically should be policyError
		return verif, failError("message contains an insecure body length tag")
	}

	// Parse body hash and signature
	bodyHashed, err := decodeBase64String(params["bh"])
	if err != nil {
		return verif, permFailError("malformed body hash: " + err.Error())
	}
	sig, err := decodeBase64String(params["b"])
	if err != nil {
		return verif, permFailError("malformed signature: " + err.Error())
	}

	// Check body hash
	hasher := hash.New()
	wc := canonicalizers[bodyCan].CanonicalizeBody(hasher)
	if _, err := io.Copy(wc, r); err != nil {
		return verif, err
	}
	if err := wc.Close(); err != nil {
		return verif, err
	}
	if subtle.ConstantTimeCompare(hasher.Sum(nil), bodyHashed) != 1 {
		return verif, failError("body hash did not verify")
	}

	// Compute data hash
	hasher.Reset()
	picker := newHeaderPicker(h)
	for _, key := range headerKeys {
		kv := picker.Pick(key)
		if kv == "" {
			// The field MAY contain names of header fields that do not exist
			// when signed; nonexistent header fields do not contribute to the
			// signature computation
			continue
		}

		kv = canonicalizers[headerCan].CanonicalizeHeader(kv)
		if _, err := hasher.Write([]byte(kv)); err != nil {
			return verif, err
		}
	}
	canSigField := removeSignature(sigField)
	canSigField = canonicalizers[headerCan].CanonicalizeHeader(canSigField)
	canSigField = strings.TrimRight(canSigField, "\r\n")
	if _, err := hasher.Write([]byte(canSigField)); err != nil {
		return verif, err
	}
	hashed := hasher.Sum(nil)

	// Check signature
	if err := res.Verifier.Verify(hash, hashed, sig); err != nil {
		return verif, failError("signature did not verify: " + err.Error())
	}

	return verif, nil
}

func parseTagList(s string) []string {
	tags := strings.Split(s, ":")
	for i, t := range tags {
		tags[i] = stripWhitespace(t)
	}
	return tags
}

func parseCanonicalization(s string) (headerCan, bodyCan Canonicalization) {
	headerCan = CanonicalizationSimple
	bodyCan = CanonicalizationSimple

	cans := strings.SplitN(stripWhitespace(s), "/", 2)
	if cans[0] != "" {
		headerCan = Canonicalization(cans[0])
	}
	if len(cans) > 1 {
		bodyCan = Canonicalization(cans[1])
	}
	return
}

func parseTime(s string) (time.Time, error) {
	sec, err := strconv.ParseInt(stripWhitespace(s), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(sec, 0), nil
}

func decodeBase64String(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(stripWhitespace(s))
}

func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

var sigRegex = regexp.MustCompile(`(b\s*=)[^;]+`)

func removeSignature(s string) string {
	return sigRegex.ReplaceAllString(s, "$1")
}
