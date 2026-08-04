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

	// carrier-grade NAT IP space, used by Tailscale among others as private space
	cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")
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
	ip = ip.Unmap()           // remove 6-in-4 mapping, needed for (netip.Prefix).Contains()
	return ip.IsLoopback() || // localhost (127.0.0.0/8 and ::1)
		ip.IsUnspecified() || // 0.0.0.0 and ::0 redirect to localhost on Linux
		ip.IsMulticast() || // multicast addresses
		ip.IsPrivate() || // private spaces like 192.168.0.0/16
		ip.IsLinkLocalUnicast() || // link-local addresses like 169.254.169.254
		cgnatPrefix.Contains(ip) // CGNAT space, 100.64.0.0/10
	// (IsLinkLocalMulticast and IsInterfaceLocalMulticast are covered by IsMulticast)
}
