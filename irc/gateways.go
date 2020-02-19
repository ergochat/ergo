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
	"time"

	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/utils"
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
	PasswordString string `yaml:"password"`
	Password       []byte `yaml:"password-bytes"`
	Fingerprint    string
	Hosts          []string
	allowedNets    []net.IPNet
}

// Populate fills out our password or fingerprint.
func (wc *webircConfig) Populate() (err error) {
	if wc.Fingerprint == "" && wc.PasswordString == "" {
		err = ErrNoFingerprintOrPassword
	}

	if err == nil && wc.PasswordString != "" {
		wc.Password, err = decodeLegacyPasswordHash(wc.PasswordString)
	}

	if err == nil && wc.Fingerprint != "" {
		wc.Fingerprint, err = utils.NormalizeCertfp(wc.Fingerprint)
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
	if session.isTor {
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
	// successfully added a limiter entry for the proxied IP;
	// remove the entry for the real IP if applicable (#197)
	client.server.connectionLimiter.RemoveClient(session.realIP)

	// given IP is sane! override the client's current IP
	client.server.logger.Info("localconnect-ip", "Accepted proxy IP for client", parsedProxiedIP.String())

	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	client.proxiedIP = parsedProxiedIP
	session.proxiedIP = parsedProxiedIP
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

// read a PROXY line one byte at a time, to ensure we don't read anything beyond
// that into a buffer, which would break the TLS handshake
func readRawProxyLine(conn net.Conn) (result string) {
	// normally this is covered by ping timeouts, but we're doing this outside
	// of the normal client goroutine:
	conn.SetDeadline(time.Now().Add(time.Minute))
	defer conn.SetDeadline(time.Time{})

	var buf [maxProxyLineLen]byte
	oneByte := make([]byte, 1)
	i := 0
	for i < maxProxyLineLen {
		n, err := conn.Read(oneByte)
		if err != nil {
			return
		} else if n == 1 {
			buf[i] = oneByte[0]
			if buf[i] == '\n' {
				candidate := string(buf[0 : i+1])
				if strings.HasPrefix(candidate, "PROXY") {
					return candidate
				} else {
					return
				}
			}
			i += 1
		}
	}

	// no \r\n, fail out
	return
}
