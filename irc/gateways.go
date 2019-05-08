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

	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/utils"
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
	allowedNets    []net.IPNet
}

// Populate fills out our password or fingerprint.
func (wc *webircConfig) Populate() (err error) {
	if wc.Fingerprint == "" && wc.PasswordString == "" {
		return ErrNoFingerprintOrPassword
	}

	if wc.PasswordString != "" {
		wc.Password, err = decodeLegacyPasswordHash(wc.PasswordString)
	}

	if err == nil {
		wc.allowedNets, err = utils.ParseNetList(wc.Hosts)
	}

	return err
}

// ApplyProxiedIP applies the given IP to the client.
func (client *Client) ApplyProxiedIP(session *Session, proxiedIP string, tls bool) (success bool) {
	// PROXY and WEBIRC are never accepted from a Tor listener, even if the address itself
	// is whitelisted:
	if client.isTor {
		return false
	}

	// ensure IP is sane
	parsedProxiedIP := net.ParseIP(proxiedIP).To16()
	if parsedProxiedIP == nil {
		client.Quit(fmt.Sprintf(client.t("Proxied IP address is not valid: [%s]"), proxiedIP), session)
		return false
	}

	isBanned, banMsg := client.server.checkBans(parsedProxiedIP)
	if isBanned {
		client.Quit(banMsg, session)
		return false
	}

	// given IP is sane! override the client's current IP
	ipstring := parsedProxiedIP.String()
	client.server.logger.Info("localconnect-ip", "Accepted proxy IP for client", ipstring)
	rawHostname := utils.LookupHostname(ipstring)

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	session.proxiedIP = parsedProxiedIP
	client.proxiedIP = parsedProxiedIP
	session.rawHostname = rawHostname
	client.rawHostname = rawHostname
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
func handleProxyCommand(server *Server, client *Client, session *Session, line string) (err error) {
	defer func() {
		if err != nil {
			client.Quit(client.t("Bad or unauthorized PROXY command"), session)
		}
	}()

	params := strings.Fields(line)
	if len(params) != 6 {
		return errBadProxyLine
	}

	if utils.IPInNets(client.realIP, server.Config().Server.proxyAllowedFromNets) {
		// assume PROXY connections are always secure
		if client.ApplyProxiedIP(session, params[2], true) {
			return nil
		} else {
			return errBadProxyLine
		}
	}

	// real source IP is not authorized to issue PROXY:
	return errBadGatewayAddress
}
