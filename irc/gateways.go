// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/unendingPattern/oragono/irc/modes"
	"github.com/unendingPattern/oragono/irc/utils"
)

var (
	errBadGatewayAddress = errors.New("PROXY/WEBIRC commands are not accepted from this IP address")
	errBadProxyLine      = errors.New("Invalid PROXY/WEBIRC command")
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
		wc.Password, err = decodeLegacyPasswordHash(wc.PasswordString)
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
func (client *Client) ApplyProxiedIP(proxiedIP string, tls bool) (success bool) {
	// ensure IP is sane
	parsedProxiedIP := net.ParseIP(proxiedIP)
	if parsedProxiedIP == nil {
		client.Quit(fmt.Sprintf(client.t("Proxied IP address is not valid: [%s]"), proxiedIP))
		return false
	}

	// undo any mapping of v4 addresses into the v6 space: https://stackoverflow.com/a/1618259
	// this is how a typical stunnel4 deployment on Linux will handle dual-stack
	unmappedIP := parsedProxiedIP.To4()
	if unmappedIP != nil {
		parsedProxiedIP = unmappedIP
	}

	isBanned, banMsg := client.server.checkBans(parsedProxiedIP)
	if isBanned {
		client.Quit(banMsg)
		return false
	}

	// given IP is sane! override the client's current IP
	rawHostname := utils.LookupHostname(parsedProxiedIP.String())
	client.stateMutex.Lock()
	client.proxiedIP = parsedProxiedIP
	client.rawHostname = rawHostname
	client.stateMutex.Unlock()
	// nickmask will be updated when the client completes registration

	// set tls info
	client.certfp = ""
	client.SetMode(modes.TLS, tls)

	return true
}

// handle the PROXY command: http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
// PROXY must be sent as the first message in the session and has the syntax:
// PROXY TCP[46] SOURCEIP DESTIP SOURCEPORT DESTPORT\r\n
// unfortunately, an ipv6 SOURCEIP can start with a double colon; in this case,
// the message is invalid IRC and can't be parsed normally, hence the special handling.
func handleProxyCommand(server *Server, client *Client, line string) (err error) {
	defer func() {
		if err != nil {
			client.Quit(client.t("Bad or unauthorized PROXY command"))
		}
	}()

	params := strings.Fields(line)
	if len(params) != 6 {
		return errBadProxyLine
	}

	for _, gateway := range server.ProxyAllowedFrom() {
		if isGatewayAllowed(client.socket.conn.RemoteAddr(), gateway) {
			// assume PROXY connections are always secure
			if client.ApplyProxiedIP(params[2], true) {
				return nil
			} else {
				return errBadProxyLine
			}
		}
	}

	// real source IP is not authorized to issue PROXY:
	return errBadGatewayAddress
}
