// Package dkim provides tools for signing and verify a email according to RFC 6376
package dkim

import (
	"bytes"
	"container/list"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"hash"
	"regexp"
	"strings"
	"time"
)

const (
	CRLF                = "\r\n"
	TAB                 = " "
	FWS                 = CRLF + TAB
	MaxHeaderLineLength = 70
)

type verifyOutput int

const (
	SUCCESS verifyOutput = 1 + iota
	PERMFAIL
	TEMPFAIL
	NOTSIGNED
	TESTINGSUCCESS
	TESTINGPERMFAIL
	TESTINGTEMPFAIL
)

// sigOptions represents signing options
type SigOptions struct {

	// DKIM version (default 1)
	Version uint

	// Private key used for signing (required)
	PrivateKey []byte

	// Domain (required)
	Domain string

	// Selector (required)
	Selector string

	// The Agent of User IDentifier
	Auid string

	// Message canonicalization (plain-text; OPTIONAL, default is
	// "simple/simple").  This tag informs the Verifier of the type of
	// canonicalization used to prepare the message for signing.
	Canonicalization string

	// The algorithm used to generate the signature
	//"rsa-sha1" or "rsa-sha256"
	Algo string

	// Signed header fields
	Headers []string

	// Body length count( if set to 0 this tag is ommited in Dkim header)
	BodyLength uint

	// Query Methods used to retrieve the public key
	QueryMethods []string

	// Add a signature timestamp
	AddSignatureTimestamp bool

	// Time validity of the signature (0=never)
	SignatureExpireIn uint64

	// CopiedHeaderFileds
	CopiedHeaderFields []string
}

// NewSigOptions returns new sigoption with some defaults value
func NewSigOptions() SigOptions {
	return SigOptions{
		Version:               1,
		Canonicalization:      "simple/simple",
		Algo:                  "rsa-sha256",
		Headers:               []string{"from"},
		BodyLength:            0,
		QueryMethods:          []string{"dns/txt"},
		AddSignatureTimestamp: true,
		SignatureExpireIn:     0,
	}
}

// Sign signs an email
func Sign(email *[]byte, options SigOptions) error {
	var privateKey *rsa.PrivateKey
	var err error

	// PrivateKey
	if len(options.PrivateKey) == 0 {
		return ErrSignPrivateKeyRequired
	}
	d, _ := pem.Decode(options.PrivateKey)
	if d == nil {
		return ErrCandNotParsePrivateKey
	}

	// try to parse it as PKCS1 otherwise try PKCS8
	if key, err := x509.ParsePKCS1PrivateKey(d.Bytes); err != nil {
		if key, err := x509.ParsePKCS8PrivateKey(d.Bytes); err != nil {
			return ErrCandNotParsePrivateKey
		} else {
			privateKey = key.(*rsa.PrivateKey)
		}
	} else {
		privateKey = key
	}

	// Domain required
	if options.Domain == "" {
		return ErrSignDomainRequired
	}

	// Selector required
	if options.Selector == "" {
		return ErrSignSelectorRequired
	}

	// Canonicalization
	options.Canonicalization, err = validateCanonicalization(strings.ToLower(options.Canonicalization))
	if err != nil {
		return err
	}

	// Algo
	options.Algo = strings.ToLower(options.Algo)
	if options.Algo != "rsa-sha1" && options.Algo != "rsa-sha256" {
		return ErrSignBadAlgo
	}

	// Header must contain "from"
	hasFrom := false
	for i, h := range options.Headers {
		h = strings.ToLower(h)
		options.Headers[i] = h
		if h == "from" {
			hasFrom = true
		}
	}
	if !hasFrom {
		return ErrSignHeaderShouldContainsFrom
	}

	// Normalize
	headers, body, err := canonicalize(email, options.Canonicalization, options.Headers)
	if err != nil {
		return err
	}

	signHash := strings.Split(options.Algo, "-")

	// hash body
	bodyHash, err := getBodyHash(&body, signHash[1], options.BodyLength)
	if err != nil {
		return err
	}

	// Get dkim header base
	dkimHeader := newDkimHeaderBySigOptions(options)
	dHeader := dkimHeader.getHeaderBaseForSigning(bodyHash)

	canonicalizations := strings.Split(options.Canonicalization, "/")
	dHeaderCanonicalized, err := canonicalizeHeader(dHeader, canonicalizations[0])
	if err != nil {
		return err
	}
	headers = append(headers, []byte(dHeaderCanonicalized)...)
	headers = bytes.TrimRight(headers, " \r\n")

	// sign
	sig, err := getSignature(&headers, privateKey, signHash[1])

	// add to DKIM-Header
	subh := ""
	l := len(subh)
	for _, c := range sig {
		subh += string(c)
		l++
		if l >= MaxHeaderLineLength {
			dHeader += subh + FWS
			subh = ""
			l = 0
		}
	}
	dHeader += subh + CRLF
	*email = append([]byte(dHeader), *email...)
	return nil
}

// Verify verifies an email an return
// state: SUCCESS or PERMFAIL or TEMPFAIL, TESTINGSUCCESS, TESTINGPERMFAIL
// TESTINGTEMPFAIL or NOTSIGNED
// error: if an error occurs during verification
func Verify(email *[]byte, opts ...DNSOpt) (verifyOutput, error) {
	// parse email
	dkimHeader, err := GetHeader(email)
	if err != nil {
		if err == ErrDkimHeaderNotFound {
			return NOTSIGNED, ErrDkimHeaderNotFound
		}
		return PERMFAIL, err
	}

	// we do not set query method because if it's others, validation failed earlier
	pubKey, verifyOutputOnError, err := NewPubKeyRespFromDNS(dkimHeader.Selector, dkimHeader.Domain, opts...)
	if err != nil {
		// fix https://github.com/toorop/go-dkim/issues/1
		//return getVerifyOutput(verifyOutputOnError, err, pubKey.FlagTesting)
		return verifyOutputOnError, err
	}

	// Normalize
	headers, body, err := canonicalize(email, dkimHeader.MessageCanonicalization, dkimHeader.Headers)
	if err != nil {
		return getVerifyOutput(PERMFAIL, err, pubKey.FlagTesting)
	}
	sigHash := strings.Split(dkimHeader.Algorithm, "-")
	// check if hash algo are compatible
	compatible := false
	for _, algo := range pubKey.HashAlgo {
		if sigHash[1] == algo {
			compatible = true
			break
		}
	}
	if !compatible {
		return getVerifyOutput(PERMFAIL, ErrVerifyInappropriateHashAlgo, pubKey.FlagTesting)
	}

	// expired ?
	if !dkimHeader.SignatureExpiration.IsZero() && dkimHeader.SignatureExpiration.Second() < time.Now().Second() {
		return getVerifyOutput(PERMFAIL, ErrVerifySignatureHasExpired, pubKey.FlagTesting)

	}

	//println("|" + string(body) + "|")
	// get body hash
	bodyHash, err := getBodyHash(&body, sigHash[1], dkimHeader.BodyLength)
	if err != nil {
		return getVerifyOutput(PERMFAIL, err, pubKey.FlagTesting)
	}
	//println(bodyHash)
	if bodyHash != dkimHeader.BodyHash {
		return getVerifyOutput(PERMFAIL, ErrVerifyBodyHash, pubKey.FlagTesting)
	}

	// compute sig
	dkimHeaderCano, err := canonicalizeHeader(dkimHeader.rawForSign, strings.Split(dkimHeader.MessageCanonicalization, "/")[0])
	if err != nil {
		return getVerifyOutput(TEMPFAIL, err, pubKey.FlagTesting)
	}
	toSignStr := string(headers) + dkimHeaderCano
	toSign := bytes.TrimRight([]byte(toSignStr), " \r\n")

	err = verifySignature(toSign, dkimHeader.SignatureData, &pubKey.PubKey, sigHash[1])
	if err != nil {
		return getVerifyOutput(PERMFAIL, err, pubKey.FlagTesting)
	}
	return SUCCESS, nil
}

// getVerifyOutput returns output of verify fct according to the testing flag
func getVerifyOutput(status verifyOutput, err error, flagTesting bool) (verifyOutput, error) {
	if !flagTesting {
		return status, err
	}
	switch status {
	case SUCCESS:
		return TESTINGSUCCESS, err
	case PERMFAIL:
		return TESTINGPERMFAIL, err
	case TEMPFAIL:
		return TESTINGTEMPFAIL, err
	}
	// should never happen but compilator sream whithout return
	return status, err
}

// canonicalize returns canonicalized version of header and body
func canonicalize(email *[]byte, cano string, h []string) (headers, body []byte, err error) {
	body = []byte{}
	rxReduceWS := regexp.MustCompile(`[ \t]+`)

	rawHeaders, rawBody, err := getHeadersBody(email)
	if err != nil {
		return nil, nil, err
	}

	canonicalizations := strings.Split(cano, "/")

	// canonicalyze header
	headersList, err := getHeadersList(&rawHeaders)

	// pour chaque header a conserver on traverse tous les headers dispo
	// If multi instance of a field we must keep it from the bottom to the top
	var match *list.Element
	headersToKeepList := list.New()

	for _, headerToKeep := range h {
		match = nil
		headerToKeepToLower := strings.ToLower(headerToKeep)
		for e := headersList.Front(); e != nil; e = e.Next() {
			//fmt.Printf("|%s|\n", e.Value.(string))
			t := strings.Split(e.Value.(string), ":")
			if strings.ToLower(t[0]) == headerToKeepToLower {
				match = e
			}
		}
		if match != nil {
			headersToKeepList.PushBack(match.Value.(string) + "\r\n")
			headersList.Remove(match)
		}
	}

	//if canonicalizations[0] == "simple" {
	for e := headersToKeepList.Front(); e != nil; e = e.Next() {
		cHeader, err := canonicalizeHeader(e.Value.(string), canonicalizations[0])
		if err != nil {
			return headers, body, err
		}
		headers = append(headers, []byte(cHeader)...)
	}
	// canonicalyze body
	if canonicalizations[1] == "simple" {
		// simple
		// The "simple" body canonicalization algorithm ignores all empty lines
		// at the end of the message body.  An empty line is a line of zero
		// length after removal of the line terminator.  If there is no body or
		// no trailing CRLF on the message body, a CRLF is added.  It makes no
		// other changes to the message body.  In more formal terms, the
		// "simple" body canonicalization algorithm converts "*CRLF" at the end
		// of the body to a single "CRLF".
		// Note that a completely empty or missing body is canonicalized as a
		// single "CRLF"; that is, the canonicalized length will be 2 octets.
		body = bytes.TrimRight(rawBody, "\r\n")
		body = append(body, []byte{13, 10}...)
	} else {
		// relaxed
		// Ignore all whitespace at the end of lines.  Implementations
		// MUST NOT remove the CRLF at the end of the line.
		// Reduce all sequences of WSP within a line to a single SP
		// character.
		// Ignore all empty lines at the end of the message body.  "Empty
		// line" is defined in Section 3.4.3.  If the body is non-empty but
		// does not end with a CRLF, a CRLF is added.  (For email, this is
		// only possible when using extensions to SMTP or non-SMTP transport
		// mechanisms.)
		rawBody = rxReduceWS.ReplaceAll(rawBody, []byte(" "))
		for _, line := range bytes.SplitAfter(rawBody, []byte{10}) {
			line = bytes.TrimRight(line, " \r\n")
			body = append(body, line...)
			body = append(body, []byte{13, 10}...)
		}
		body = bytes.TrimRight(body, "\r\n")
		body = append(body, []byte{13, 10}...)

	}
	return
}

// canonicalizeHeader returns canonicalized version of header
func canonicalizeHeader(header string, algo string) (string, error) {
	//rxReduceWS := regexp.MustCompile(`[ \t]+`)
	if algo == "simple" {
		// The "simple" header canonicalization algorithm does not change header
		// fields in any way.  Header fields MUST be presented to the signing or
		// verification algorithm exactly as they are in the message being
		// signed or verified.  In particular, header field names MUST NOT be
		// case folded and whitespace MUST NOT be changed.
		return header, nil
	} else if algo == "relaxed" {
		// The "relaxed" header canonicalization algorithm MUST apply the
		// following steps in order:

		// Convert all header field names (not the header field values) to
		// lowercase.  For example, convert "SUBJect: AbC" to "subject: AbC".

		// Unfold all header field continuation lines as described in
		// [RFC5322]; in particular, lines with terminators embedded in
		// continued header field values (that is, CRLF sequences followed by
		// WSP) MUST be interpreted without the CRLF.  Implementations MUST
		// NOT remove the CRLF at the end of the header field value.

		// Convert all sequences of one or more WSP characters to a single SP
		// character.  WSP characters here include those before and after a
		// line folding boundary.

		// Delete all WSP characters at the end of each unfolded header field
		// value.

		// Delete any WSP characters remaining before and after the colon
		// separating the header field name from the header field value.  The
		// colon separator MUST be retained.
		kv := strings.SplitN(header, ":", 2)
		if len(kv) != 2 {
			return header, ErrBadMailFormatHeaders
		}
		k := strings.ToLower(kv[0])
		k = strings.TrimSpace(k)
		v := removeFWS(kv[1])
		//v = rxReduceWS.ReplaceAllString(v, " ")
		//v = strings.TrimSpace(v)
		return k + ":" + v + CRLF, nil
	}
	return header, ErrSignBadCanonicalization
}

// getBodyHash return the hash (bas64encoded) of the body
func getBodyHash(body *[]byte, algo string, bodyLength uint) (string, error) {
	var h hash.Hash
	if algo == "sha1" {
		h = sha1.New()
	} else {
		h = sha256.New()
	}
	toH := *body
	// if l tag (body length)
	if bodyLength != 0 {
		if uint(len(toH)) < bodyLength {
			return "", ErrBadDKimTagLBodyTooShort
		}
		toH = toH[0:bodyLength]
	}

	h.Write(toH)
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// getSignature return signature of toSign using key
func getSignature(toSign *[]byte, key *rsa.PrivateKey, algo string) (string, error) {
	var h1 hash.Hash
	var h2 crypto.Hash
	switch algo {
	case "sha1":
		h1 = sha1.New()
		h2 = crypto.SHA1
		break
	case "sha256":
		h1 = sha256.New()
		h2 = crypto.SHA256
		break
	default:
		return "", ErrVerifyInappropriateHashAlgo
	}

	// sign
	h1.Write(*toSign)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, h2, h1.Sum(nil))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// verifySignature verify signature from pubkey
func verifySignature(toSign []byte, sig64 string, key *rsa.PublicKey, algo string) error {
	var h1 hash.Hash
	var h2 crypto.Hash
	switch algo {
	case "sha1":
		h1 = sha1.New()
		h2 = crypto.SHA1
		break
	case "sha256":
		h1 = sha256.New()
		h2 = crypto.SHA256
		break
	default:
		return ErrVerifyInappropriateHashAlgo
	}

	h1.Write(toSign)
	sig, err := base64.StdEncoding.DecodeString(sig64)
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(key, h2, h1.Sum(nil), sig)
}

// removeFWS removes all FWS from string
func removeFWS(in string) string {
	rxReduceWS := regexp.MustCompile(`[ \t]+`)
	out := strings.Replace(in, "\n", "", -1)
	out = strings.Replace(out, "\r", "", -1)
	out = rxReduceWS.ReplaceAllString(out, " ")
	return strings.TrimSpace(out)
}

// validateCanonicalization validate canonicalization (c flag)
func validateCanonicalization(cano string) (string, error) {
	p := strings.Split(cano, "/")
	if len(p) > 2 {
		return "", ErrSignBadCanonicalization
	}
	if len(p) == 1 {
		cano = cano + "/simple"
	}
	for _, c := range p {
		if c != "simple" && c != "relaxed" {
			return "", ErrSignBadCanonicalization
		}
	}
	return cano, nil
}

// getHeadersList returns headers as list
func getHeadersList(rawHeader *[]byte) (*list.List, error) {
	headersList := list.New()
	currentHeader := []byte{}
	for _, line := range bytes.SplitAfter(*rawHeader, []byte{10}) {
		if line[0] == 32 || line[0] == 9 {
			if len(currentHeader) == 0 {
				return headersList, ErrBadMailFormatHeaders
			}
			currentHeader = append(currentHeader, line...)
		} else {
			// New header, save current if exists
			if len(currentHeader) != 0 {
				headersList.PushBack(string(bytes.TrimRight(currentHeader, "\r\n")))
				currentHeader = []byte{}
			}
			currentHeader = append(currentHeader, line...)
		}
	}
	headersList.PushBack(string(currentHeader))
	return headersList, nil
}

// getHeadersBody return headers and body
func getHeadersBody(email *[]byte) ([]byte, []byte, error) {
	substitutedEmail := *email

	// only replace \n with \r\n when \r\n\r\n not exists
	if bytes.Index(*email, []byte{13, 10, 13, 10}) < 0 {
		// \n -> \r\n
		substitutedEmail = bytes.Replace(*email, []byte{10}, []byte{13, 10}, -1)
	}

	parts := bytes.SplitN(substitutedEmail, []byte{13, 10, 13, 10}, 2)
	if len(parts) != 2 {
		return []byte{}, []byte{}, ErrBadMailFormat
	}
	// Empty body
	if len(parts[1]) == 0 {
		parts[1] = []byte{13, 10}
	}
	return parts[0], parts[1], nil
}
