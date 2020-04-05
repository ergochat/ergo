package dkim

import (
	"errors"
)

var (
	// ErrSignPrivateKeyRequired when there not private key in config
	ErrSignPrivateKeyRequired = errors.New("PrivateKey is required")

	// ErrSignDomainRequired when there is no domain defined in config
	ErrSignDomainRequired = errors.New("Domain is required")

	// ErrSignSelectorRequired when there is no Selcteir defined in config
	ErrSignSelectorRequired = errors.New("Selector is required")

	// ErrSignHeaderShouldContainsFrom If Headers is specified it should at least contain 'from'
	ErrSignHeaderShouldContainsFrom = errors.New("header must contains 'from' field")

	// ErrSignBadCanonicalization If bad Canonicalization parameter
	ErrSignBadCanonicalization = errors.New("bad Canonicalization parameter")

	// ErrCandNotParsePrivateKey when unable to parse private key
	ErrCandNotParsePrivateKey = errors.New("can not parse private key, check format (pem) and validity")

	// ErrSignBadAlgo Bad algorithm
	ErrSignBadAlgo = errors.New("bad algorithm. Only rsa-sha1 or rsa-sha256 are permitted")

	// ErrBadMailFormat unable to parse mail
	ErrBadMailFormat = errors.New("bad mail format")

	// ErrBadMailFormatHeaders bad headers format (not DKIM Header)
	ErrBadMailFormatHeaders = errors.New("bad mail format found in headers")

	// ErrBadDKimTagLBodyTooShort bad l tag
	ErrBadDKimTagLBodyTooShort = errors.New("bad tag l or bodyLength option. Body length < l value")

	// ErrDkimHeaderBadFormat when errors found in DKIM header
	ErrDkimHeaderBadFormat = errors.New("bad DKIM header format")

	// ErrDkimHeaderNotFound when there's no DKIM-Signature header in an email we have to verify
	ErrDkimHeaderNotFound = errors.New("no DKIM-Signature header field found ")

	// ErrDkimHeaderBTagNotFound when there's no b tag
	ErrDkimHeaderBTagNotFound = errors.New("no tag 'b' found in dkim header")

	// ErrDkimHeaderNoFromInHTag when from is missing in h tag
	ErrDkimHeaderNoFromInHTag = errors.New("'from' header is missing in h tag")

	// ErrDkimHeaderMissingRequiredTag when a required tag is missing
	ErrDkimHeaderMissingRequiredTag = errors.New("signature missing required tag")

	// ErrDkimHeaderDomainMismatch if i tag is not a sub domain of d tag
	ErrDkimHeaderDomainMismatch = errors.New("domain mismatch")

	// ErrDkimVersionNotsupported version not supported
	ErrDkimVersionNotsupported = errors.New("incompatible version")

	// Query method unsupported
	errQueryMethodNotsupported = errors.New("query method not supported")

	// ErrVerifyBodyHash when body hash doesn't verify
	ErrVerifyBodyHash = errors.New("body hash did not verify")

	// ErrVerifyNoKeyForSignature no key
	ErrVerifyNoKeyForSignature = errors.New("no key for verify")

	// ErrVerifyKeyUnavailable when service (dns) is anavailable
	ErrVerifyKeyUnavailable = errors.New("key unavailable")

	// ErrVerifyTagVMustBeTheFirst if present the v tag must be the firts in the record
	ErrVerifyTagVMustBeTheFirst = errors.New("pub key syntax error: v tag must be the first")

	// ErrVerifyVersionMusBeDkim1 if présent flag v (version) must be DKIM1
	ErrVerifyVersionMusBeDkim1 = errors.New("flag v must be set to DKIM1")

	// ErrVerifyBadKeyType bad type for pub key (only rsa is accepted)
	ErrVerifyBadKeyType = errors.New("bad type for key type")

	// ErrVerifyRevokedKey key(s) for this selector is revoked (p is empty)
	ErrVerifyRevokedKey = errors.New("revoked key")

	// ErrVerifyBadKey when we can't parse pubkey
	ErrVerifyBadKey = errors.New("unable to parse pub key")

	// ErrVerifyNoKey when no key is found on DNS record
	ErrVerifyNoKey = errors.New("no public key found in DNS TXT")

	// ErrVerifySignatureHasExpired when signature has expired
	ErrVerifySignatureHasExpired = errors.New("signature has expired")

	// ErrVerifyInappropriateHashAlgo when h tag in pub key doesn't contain hash algo from a tag of DKIM header
	ErrVerifyInappropriateHashAlgo = errors.New("inappropriate has algorithm")
)
