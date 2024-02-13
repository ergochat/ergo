package ircutils

import (
	"encoding/base64"
	"errors"
	"strings"
)

var (
	ErrSASLLimitExceeded = errors.New("SASL total response size exceeded configured limit")
	ErrSASLTooLong       = errors.New("SASL response chunk exceeded 400-byte limit")
)

// EncodeSASLResponse encodes a raw SASL response as parameters to successive
// AUTHENTICATE commands, as described in the IRCv3 SASL specification.
func EncodeSASLResponse(raw []byte) (result []string) {
	// https://ircv3.net/specs/extensions/sasl-3.1#the-authenticate-command
	// "The response is encoded in Base64 (RFC 4648), then split to 400-byte chunks,
	// and each chunk is sent as a separate AUTHENTICATE command. Empty (zero-length)
	// responses are sent as AUTHENTICATE +. If the last chunk was exactly 400 bytes
	// long, it must also be followed by AUTHENTICATE + to signal end of response."

	if len(raw) == 0 {
		return []string{"+"}
	}

	response := base64.StdEncoding.EncodeToString(raw)
	lastLen := 0
	for len(response) > 0 {
		// TODO once we require go 1.21, this can be: lastLen = min(len(response), 400)
		lastLen = len(response)
		if lastLen > 400 {
			lastLen = 400
		}
		result = append(result, response[:lastLen])
		response = response[lastLen:]
	}

	if lastLen == 400 {
		result = append(result, "+")
	}

	return result
}

// SASLBuffer handles buffering and decoding SASL responses sent as parameters
// to AUTHENTICATE commands, as described in the IRCv3 SASL specification.
// Do not copy a SASLBuffer after first use.
type SASLBuffer struct {
	maxLength int
	buffer    strings.Builder
}

// NewSASLBuffer returns a new SASLBuffer. maxLength is the maximum amount of
// base64'ed data to buffer (0 for no limit).
func NewSASLBuffer(maxLength int) *SASLBuffer {
	result := new(SASLBuffer)
	result.Initialize(maxLength)
	return result
}

// Initialize initializes a SASLBuffer in place.
func (b *SASLBuffer) Initialize(maxLength int) {
	b.maxLength = maxLength
}

// Add processes an additional SASL response chunk sent via AUTHENTICATE.
// If the response is complete, it resets the buffer and returns the decoded
// response along with any decoding or protocol errors detected.
func (b *SASLBuffer) Add(value string) (done bool, output []byte, err error) {
	if value == "+" {
		output, err = b.getAndReset()
		return true, output, err
	}

	if len(value) > 400 {
		b.buffer.Reset()
		return true, nil, ErrSASLTooLong
	}

	if b.maxLength != 0 && (b.buffer.Len()+len(value)) > b.maxLength {
		b.buffer.Reset()
		return true, nil, ErrSASLLimitExceeded
	}

	b.buffer.WriteString(value)
	if len(value) < 400 {
		output, err = b.getAndReset()
		return true, output, err
	} else {
		// 400 bytes, wait for continuation line or +
		return false, nil, nil
	}
}

// Clear resets the buffer state.
func (b *SASLBuffer) Clear() {
	b.buffer.Reset()
}

func (b *SASLBuffer) getAndReset() (output []byte, err error) {
	output, err = base64.StdEncoding.DecodeString(b.buffer.String())
	b.buffer.Reset()
	return
}
