// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"net"

	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/passwd"
	"github.com/oragono/oragono/irc/utils"
)

type webircConfig struct {
	PasswordString string `yaml:"password"`
	Password       []byte `yaml:"password-bytes"`
	Fingerprint    string
	Hosts          []string
}

// Populate fills out our password or fingerprint.
func (wc *webircConfig) Populate() (err error) {
	if wc.Fingerprint == "" && wc.PasswordString == "" {
		return ErrNoFingerprintOrPassword
	}

	if wc.PasswordString != "" {
		var password []byte
		password, err = passwd.DecodePasswordHash(wc.PasswordString)
		wc.Password = password
	}
	return err
}

func isGatewayAllowed(addr net.Addr, gatewaySpec string) bool {
	// "localhost" includes any loopback IP or unix domain socket
	if gatewaySpec == "localhost" {
		return utils.AddrIsLocal(addr)
	}

	ip := utils.AddrToIP(addr)
	if ip == nil {
		return false
	}

	// exact IP match
	if ip.String() == gatewaySpec {
		return true
	}

	// CIDR match
	_, gatewayNet, err := net.ParseCIDR(gatewaySpec)
	if err != nil {
		return false
	}
	return gatewayNet.Contains(ip)
}

// ApplyProxiedIP applies the given IP to the client.
func (client *Client) ApplyProxiedIP(proxiedIP string, tls bool) (exiting bool) {
	// ensure IP is sane
	parsedProxiedIP := net.ParseIP(proxiedIP)
	if parsedProxiedIP == nil {
		client.Quit(fmt.Sprintf(client.t("Proxied IP address is not valid: [%s]"), proxiedIP))
		return true
	}

	isBanned, banMsg := client.server.checkBans(parsedProxiedIP)
	if isBanned {
		client.Quit(banMsg)
		return true
	}

	// given IP is sane! override the client's current IP
	client.proxiedIP = parsedProxiedIP
	client.rawHostname = utils.LookupHostname(proxiedIP)
	client.hostname = client.rawHostname

	// set tls info
	client.certfp = ""
	client.SetMode(modes.TLS, tls)

	return false
}
