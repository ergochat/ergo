// written by Daniel Oaks <daniel@danieloaks.net>
// released under the ISC license

package ircutils

import "strings"

var allowedHostnameChars = "abcdefghijklmnopqrstuvwxyz1234567890-."

// HostnameIsValid provides a way for servers to check whether a looked-up client
// hostname is valid (see InspIRCd #1033 for why this is required).
//
// This function shouldn't be called by clients since they don't need to validate
// hostnames for IRC use, just by servers that need to confirm hostnames of incoming
// clients.
//
// In addition to this function, servers should impose their own limits on max
// hostname length -- this function limits it to 200 but most servers will probably
// want to make it smaller than that.
func HostnameIsValid(hostname string) bool {
	// IRC hostnames specifically require a period, rough limit of 200 chars
	if !strings.Contains(hostname, ".") || len(hostname) < 1 || len(hostname) > 200 {
		return false
	}

	// ensure each part of hostname is valid
	for _, part := range strings.Split(hostname, ".") {
		if len(part) < 1 || len(part) > 63 || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
	}

	// ensure all chars of hostname are valid
	for _, char := range strings.Split(strings.ToLower(hostname), "") {
		if !strings.Contains(allowedHostnameChars, char) {
			return false
		}
	}

	return true
}
