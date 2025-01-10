// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"errors"
	"net"

	"github.com/ergochat/ergo/irc/flatip"
	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/utils"
)

var (
	errBadGatewayAddress = errors.New("PROXY/WEBIRC commands are not accepted from this IP address")
	errBadProxyLine      = errors.New("Invalid PROXY/WEBIRC command")
)

const (
	// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
	// "a 108-byte buffer is always enough to store all the line and a trailing zero
	// for string processing."
	maxProxyLineLen = 107
)

type webircConfig struct {
	PasswordString string  `yaml:"password"`
	Password       []byte  `yaml:"password-bytes"`
	Fingerprint    *string // legacy name for certfp, #1050
	Certfp         string
	Hosts          []string
	AcceptHostname bool `yaml:"accept-hostname"`
	allowedNets    []net.IPNet
}

// Populate fills out our password or fingerprint.
func (wc *webircConfig) Populate() (err error) {
	if wc.PasswordString != "" {
		wc.Password, err = decodeLegacyPasswordHash(wc.PasswordString)
		if err != nil {
			return
		}
	}

	certfp := wc.Certfp
	if certfp == "" && wc.Fingerprint != nil {
		certfp = *wc.Fingerprint
	}
	if certfp != "" {
		wc.Certfp, err = utils.NormalizeCertfp(certfp)
	}
	if err != nil {
		return
	}

	if wc.Certfp == "" && wc.PasswordString == "" {
		return errors.New("webirc block has no certfp or password specified")
	}

	wc.allowedNets, err = utils.ParseNetList(wc.Hosts)
	return err
}

// ApplyProxiedIP applies the given IP to the client.
func (client *Client) ApplyProxiedIP(session *Session, proxiedIP net.IP, tls bool) (err error, quitMsg string) {
	// PROXY and WEBIRC are never accepted from a Tor listener, even if the address itself
	// is whitelisted. Furthermore, don't accept PROXY or WEBIRC if we already accepted
	// a proxied IP from any source (PROXY, WEBIRC, or X-Forwarded-For):
	if session.isTor || session.proxiedIP != nil {
		return errBadProxyLine, ""
	}

	// ensure IP is sane
	if proxiedIP == nil {
		return errBadProxyLine, "proxied IP is not valid"
	}
	proxiedIP = proxiedIP.To16()

	isBanned, requireSASL, banMsg := client.server.checkBans(client.server.Config(), proxiedIP, true)
	if isBanned {
		return errBanned, banMsg
	}
	client.requireSASL = requireSASL
	if requireSASL {
		client.requireSASLMessage = banMsg
	}
	// successfully added a limiter entry for the proxied IP;
	// remove the entry for the real IP if applicable (#197)
	client.server.connectionLimiter.RemoveClient(flatip.FromNetIP(session.realIP))

	// given IP is sane! override the client's current IP
	client.server.logger.Info("connect-ip", session.connID, "Accepted proxy IP for client", proxiedIP.String())

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	client.proxiedIP = proxiedIP
	session.proxiedIP = proxiedIP
	// nickmask will be updated when the client completes registration
	// set tls info
	session.certfp = ""
	session.peerCerts = nil
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

	ip, err := utils.ParseProxyLineV1(line)
	if err != nil {
		return err
	} else if ip == nil {
		return nil
	}

	if utils.IPInNets(client.realIP, server.Config().Server.proxyAllowedFromNets) {
		// assume PROXY connections are always secure
		err, quitMsg = client.ApplyProxiedIP(session, ip, true)
		return
	} else {
		// real source IP is not authorized to issue PROXY:
		return errBadGatewayAddress
	}
}
