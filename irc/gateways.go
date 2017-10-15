// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"net"

	"github.com/oragono/oragono/irc/passwd"

	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/oragono/oragono/irc/utils"
)

type webircConfig struct {
	passwordString string `yaml:"password"`
	password       []byte `yaml:"password-bytes"`
	hosts          []string
}

// ProcessPassword populates our password.
func (wc *webircConfig) ProcessPassword() error {
	password, error := passwd.DecodePasswordHash(wc.passwordString)
	wc.password = password
	return error
}

// WEBIRC password gateway hostname ip
func webircHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// only allow unregistered clients to use this command
	if client.registered {
		return false
	}

	clientAddress := utils.IPString(client.socket.conn.RemoteAddr())
	clientHostname := client.hostname
	server.configurableStateMutex.RLock()
	defer server.configurableStateMutex.RUnlock()
	for _, info := range server.webirc {
		for _, address := range info.hosts {
			if clientHostname == address || clientAddress == address {
				// confirm password
				givenPassword := msg.Params[0]
				if passwd.ComparePasswordString(info.password, givenPassword) == nil {
					proxiedIP := msg.Params[3]

					return client.ApplyProxiedIP(proxiedIP)
				}
			}
		}
	}

	client.Quit("WEBIRC command is not usable from your address or incorrect password given")
	return true
}

// PROXY TCP4/6 SOURCEIP DESTIP SOURCEPORT DESTPORT
// http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
func proxyHandler(server *Server, client *Client, msg ircmsg.IrcMessage) bool {
	// only allow unregistered clients to use this command
	if client.registered {
		return false
	}

	clientAddress := utils.IPString(client.socket.conn.RemoteAddr())
	clientHostname := client.hostname
	server.configurableStateMutex.RLock()
	defer server.configurableStateMutex.RUnlock()
	for _, address := range server.proxyAllowedFrom {
		if clientHostname == address || clientAddress == address {
			proxiedIP := msg.Params[1]

			return client.ApplyProxiedIP(proxiedIP)
		}
	}
	client.Quit("PROXY command is not usable from your address")
	return true
}

// ApplyProxiedIP applies the given IP to the client.
func (client *Client) ApplyProxiedIP(proxiedIP string) (exiting bool) {
	// ensure IP is sane
	parsedProxiedIP := net.ParseIP(proxiedIP)
	if parsedProxiedIP == nil {
		client.Quit(fmt.Sprintf("Proxied IP address is not valid: [%s]", proxiedIP))
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
	return false
}
