package dkim

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"mime/quotedprintable"
	"net"
	"strings"
)

// PubKeyRep represents a parsed version of public key record
type PubKeyRep struct {
	Version      string
	HashAlgo     []string
	KeyType      string
	Note         string
	PubKey       rsa.PublicKey
	ServiceType  []string
	FlagTesting  bool // flag y
	FlagIMustBeD bool // flag i
}

// DNSOptions holds settings for looking up DNS records
type DNSOptions struct {
	netLookupTXT func(name string) ([]string, error)
}

// DNSOpt represents an optional setting for looking up DNS records
type DNSOpt interface {
	apply(*DNSOptions)
}

type dnsOpt func(*DNSOptions)

func (opt dnsOpt) apply(dnsOpts *DNSOptions) {
	opt(dnsOpts)
}

// DNSOptLookupTXT sets the function to use to lookup TXT records.
//
// This should probably only be used in tests.
func DNSOptLookupTXT(netLookupTXT func(name string) ([]string, error)) DNSOpt {
	return dnsOpt(func(opts *DNSOptions) {
		opts.netLookupTXT = netLookupTXT
	})
}

// NewPubKeyRespFromDNS retrieves the TXT record from DNS based on the specified domain and selector
// and parses it.
func NewPubKeyRespFromDNS(selector, domain string, opts ...DNSOpt) (*PubKeyRep, verifyOutput, error) {
	dnsOpts := DNSOptions{}

	for _, opt := range opts {
		opt.apply(&dnsOpts)
	}

	if dnsOpts.netLookupTXT == nil {
		dnsOpts.netLookupTXT = net.LookupTXT
	}

	txt, err := dnsOpts.netLookupTXT(selector + "._domainkey." + domain)
	if err != nil {
		if strings.HasSuffix(err.Error(), "no such host") {
			return nil, PERMFAIL, ErrVerifyNoKeyForSignature
		}

		return nil, TEMPFAIL, ErrVerifyKeyUnavailable
	}

	// empty record
	if len(txt) == 0 {
		return nil, PERMFAIL, ErrVerifyNoKeyForSignature
	}

	// parsing, we keep the first record
	// TODO: if there is multiple record

	return NewPubKeyResp(txt[0])
}

// NewPubKeyResp parses DKIM record (usually from DNS)
func NewPubKeyResp(dkimRecord string) (*PubKeyRep, verifyOutput, error) {
	pkr := new(PubKeyRep)
	pkr.Version = "DKIM1"
	pkr.HashAlgo = []string{"sha1", "sha256"}
	pkr.KeyType = "rsa"
	pkr.FlagTesting = false
	pkr.FlagIMustBeD = false

	p := strings.Split(dkimRecord, ";")
	for i, data := range p {
		keyVal := strings.SplitN(data, "=", 2)
		val := ""
		if len(keyVal) > 1 {
			val = strings.TrimSpace(keyVal[1])
		}
		switch strings.ToLower(strings.TrimSpace(keyVal[0])) {
		case "v":
			// RFC: is this tag is specified it MUST be the first in the record
			if i != 0 {
				return nil, PERMFAIL, ErrVerifyTagVMustBeTheFirst
			}
			pkr.Version = val
			if pkr.Version != "DKIM1" {
				return nil, PERMFAIL, ErrVerifyVersionMusBeDkim1
			}
		case "h":
			p := strings.Split(strings.ToLower(val), ":")
			pkr.HashAlgo = []string{}
			for _, h := range p {
				h = strings.TrimSpace(h)
				if h == "sha1" || h == "sha256" {
					pkr.HashAlgo = append(pkr.HashAlgo, h)
				}
			}
			// if empty switch back to default
			if len(pkr.HashAlgo) == 0 {
				pkr.HashAlgo = []string{"sha1", "sha256"}
			}
		case "k":
			if strings.ToLower(val) != "rsa" {
				return nil, PERMFAIL, ErrVerifyBadKeyType
			}
		case "n":
			qp, err := ioutil.ReadAll(quotedprintable.NewReader(strings.NewReader(val)))
			if err == nil {
				val = string(qp)
			}
			pkr.Note = val
		case "p":
			rawkey := val
			if rawkey == "" {
				return nil, PERMFAIL, ErrVerifyRevokedKey
			}
			un64, err := base64.StdEncoding.DecodeString(rawkey)
			if err != nil {
				return nil, PERMFAIL, ErrVerifyBadKey
			}
			pk, err := x509.ParsePKIXPublicKey(un64)
			if pk, ok := pk.(*rsa.PublicKey); ok {
				pkr.PubKey = *pk
			}
		case "s":
			t := strings.Split(strings.ToLower(val), ":")
			for _, tt := range t {
				tt = strings.TrimSpace(tt)
				switch tt {
				case "*":
					pkr.ServiceType = append(pkr.ServiceType, "all")
				case "email":
					pkr.ServiceType = append(pkr.ServiceType, tt)
				}
			}
		case "t":
			flags := strings.Split(strings.ToLower(val), ":")
			for _, flag := range flags {
				flag = strings.TrimSpace(flag)
				switch flag {
				case "y":
					pkr.FlagTesting = true
				case "s":
					pkr.FlagIMustBeD = true
				}
			}
		}
	}

	// if no pubkey
	if pkr.PubKey == (rsa.PublicKey{}) {
		return nil, PERMFAIL, ErrVerifyNoKey
	}

	// No service type
	if len(pkr.ServiceType) == 0 {
		pkr.ServiceType = []string{"all"}
	}

	return pkr, SUCCESS, nil
}
