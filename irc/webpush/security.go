// Copyright (c) 2024 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// Released under the MIT license
// Some portions of this code are:
// Copyright (c) 2024 Simon Ser <contact@emersion.fr>
// Originally released under the AGPLv3, relicensed to the Ergo project under the MIT license

package webpush

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
)

var (
	errInternalIP = errors.New("dialing an internal IP is forbidden")
)

func SanityCheckWebPushEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return fmt.Errorf("scheme must be HTTPS")
	}
	return nil
}

// makeExternalOnlyClient builds an http.Client that can only connect
// to external IP addresses.
func makeExternalOnlyClient() *http.Client {
	dialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			ip, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}

			parsedIP, err := netip.ParseAddr(ip)
			if err != nil {
				return err
			}

			if isInternalIP(parsedIP) {
				return errInternalIP
			}

			return nil
		},
	}

	return &http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}
}

func isInternalIP(ip netip.Addr) bool {
	return ip.IsLoopback() || ip.IsMulticast() || ip.IsPrivate()
}
