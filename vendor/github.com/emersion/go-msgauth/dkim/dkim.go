// Package dkim creates and verifies DKIM signatures, as specified in RFC 6376.
//
// # FAQ
//
// Why can't I verify a [net/mail.Message] directly? A [net/mail.Message]
// header is already parsed, and whitespace characters (especially continuation
// lines) are removed. Thus, the signature computed from the parsed header is
// not the same as the one computed from the raw header.
//
// How can I publish my public key? You have to add a TXT record to your DNS
// zone. See [RFC 6376 appendix C]. You can use the dkim-keygen tool included
// in go-msgauth to generate the key and the TXT record.
//
// [RFC 6376 appendix C]: https://tools.ietf.org/html/rfc6376#appendix-C
package dkim

import (
	"time"
)

var now = time.Now

const headerFieldName = "DKIM-Signature"
