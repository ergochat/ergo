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
func (client *Client) ApplyProxiedIP(session *Session, proxiedIP string, tls bool) (err error, quitMsg string) {
	// PROXY and WEBIRC are never accepted from a Tor listener, even if the address itself
	// is whitelisted:
	if client.isTor {
		return errBadProxyLine, ""
	}

	// ensure IP is sane
	parsedProxiedIP := net.ParseIP(proxiedIP).To16()
	if parsedProxiedIP == nil {
		return errBadProxyLine, fmt.Sprintf(client.t("Proxied IP address is not valid: [%s]"), proxiedIP)
	}

	isBanned, banMsg := client.server.checkBans(parsedProxiedIP)
	if isBanned {
		return errBanned, banMsg
	}

	// given IP is sane! override the client's current IP
	ipstring := parsedProxiedIP.String()
	client.server.logger.Info("localconnect-ip", "Accepted proxy IP for client", ipstring)
	rawHostname := utils.LookupHostname(ipstring)
	cloakedHostname := client.server.Config().Server.Cloaks.ComputeCloak(parsedProxiedIP)

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	session.proxiedIP = parsedProxiedIP
	client.proxiedIP = parsedProxiedIP
	session.rawHostname = rawHostname
	client.rawHostname = rawHostname
	client.cloakedHostname = cloakedHostname
	// nickmask will be updated when the client completes registration
	// set tls info
	client.certfp = ""
	client.SetMode(modes.TLS, tls)

	return nil, ""
}

// handle the PROXY command: http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
// PROXY must be sent as the first message in the session and has the syntax:
// PROXY TCP[46] SOURCEIP DESTIP SOURCEPORT DESTPORT\r\n
// unfortunately, an ipv6 SOURCEIP can start with a double colon; in this case,
// the message is invalid IRC and can't be parsed normally, hence the special handling.
func handleProxyCommand(server *Server, client *Client, session *Session, line string) (err error) {
	var quitMsg string
	defer func() {
		if err != nil {
			if quitMsg == "" {
				quitMsg = client.t("Bad or unauthorized PROXY command")
			}
			client.Quit(quitMsg, session)
		}
	}()

	params := strings.Fields(line)
	if len(params) != 6 {
		return errBadProxyLine
	}

	if utils.IPInNets(client.realIP, server.Config().Server.proxyAllowedFromNets) {
		// assume PROXY connections are always secure
		err, quitMsg = client.ApplyProxiedIP(session, params[2], true)
		return
	} else {
		// real source IP is not authorized to issue PROXY:
		return errBadGatewayAddress
	}
}
