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

	"github.com/oragono/oragono/irc/passwd"

	"github.com/goshuirc/irc-go/ircmsg"
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
		return errors.New("Fingerprint or password needs to be specified")
	}

	if wc.PasswordString != "" {
		var password []byte
		password, err = passwd.DecodePasswordHash(wc.PasswordString)
		wc.Password = password
	}
	return err
}

// WEBIRC <password> <gateway> <hostname> <ip> [:flag1 flag2=x flag3]
func webircHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// only allow unregistered clients to use this command
	if client.registered || client.proxiedIP != "" {
		return false
	}

	// process flags
	var secure bool
	if 4 < len(msg.Params) {
		for _, x := range strings.Split(msg.Params[4], " ") {
			// split into key=value
			var key string
			if strings.Contains(x, "=") {
				y := strings.SplitN(x, "=", 2)
				key, _ = y[0], y[1]
			} else {
				key = x
			}

			// only accept "tls" flag if the gateway's connection to us is secure as well
			if strings.ToLower(key) == "tls" && client.flags[TLS] {
				secure = true
			}
		}
	}

	clientAddress := utils.IPString(client.socket.conn.RemoteAddr())
	clientHostname := client.hostname
	for _, info := range server.WebIRCConfig() {
		for _, address := range info.Hosts {
			if clientHostname == address || clientAddress == address {
				// confirm password and/or fingerprint
				givenPassword := msg.Params[0]
				if 0 < len(info.Password) && passwd.ComparePasswordString(info.Password, givenPassword) != nil {
					continue
				}
				if 0 < len(info.Fingerprint) && client.certfp != info.Fingerprint {
					continue
				}

				proxiedIP := msg.Params[3]
				return client.ApplyProxiedIP(proxiedIP, secure)
			}
		}
	}

	client.Quit(client.t("WEBIRC command is not usable from your address or incorrect password given"))
	return true
}

// PROXY TCP4/6 SOURCEIP DESTIP SOURCEPORT DESTPORT
// http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
func proxyHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// only allow unregistered clients to use this command
	if client.registered || client.proxiedIP != "" {
		return false
	}

	clientAddress := utils.IPString(client.socket.conn.RemoteAddr())
	clientHostname := client.hostname
	for _, address := range server.ProxyAllowedFrom() {
		if clientHostname == address || clientAddress == address {
			proxiedIP := msg.Params[1]

			// assume PROXY connections are always secure
			return client.ApplyProxiedIP(proxiedIP, true)
		}
	}
	client.Quit(client.t("PROXY command is not usable from your address"))
	return true
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
	client.proxiedIP = proxiedIP
	client.rawHostname = utils.LookupHostname(proxiedIP)
	client.hostname = client.rawHostname

	// set tls info
	client.certfp = ""
	if tls {
		client.flags[TLS] = true
	} else {
		delete(client.flags, TLS)
	}

	return false
}
