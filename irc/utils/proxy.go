// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// TODO: handle PROXY protocol v2 (the binary protocol)

const (
	// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
	// "a 108-byte buffer is always enough to store all the line and a trailing zero
	// for string processing."
	maxProxyLineLen = 107
)

var (
	ErrBadProxyLine = errors.New("invalid PROXY line")
	// TODO(golang/go#4373): replace this with the stdlib ErrNetClosing
	ErrNetClosing = errors.New("use of closed network connection")
)

// ListenerConfig is all the information about how to process
// incoming IRC connections on a listener.
type ListenerConfig struct {
	TLSConfig     *tls.Config
	ProxyDeadline time.Duration
	RequireProxy  bool
	// these are just metadata for easier tracking,
	// they are not used by ReloadableListener:
	Tor       bool
	STSOnly   bool
	WebSocket bool
}

// read a PROXY line one byte at a time, to ensure we don't read anything beyond
// that into a buffer, which would break the TLS handshake
func readRawProxyLine(conn net.Conn, deadline time.Duration) (result string) {
	// normally this is covered by ping timeouts, but we're doing this outside
	// of the normal client goroutine:
	conn.SetDeadline(time.Now().Add(deadline))
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

// ParseProxyLine parses a PROXY protocol (v1) line and returns the remote IP.
func ParseProxyLine(line string) (ip net.IP, err error) {
	params := strings.Fields(line)
	if len(params) != 6 || params[0] != "PROXY" {
		return nil, ErrBadProxyLine
	}
	ip = net.ParseIP(params[2])
	if ip == nil {
		return nil, ErrBadProxyLine
	}
	return ip.To16(), nil
}

/// ProxiedConnection is a net.Conn with some additional data stapled to it;
// the proxied IP, if one was read via the PROXY protocol, and the listener
// configuration.
type ProxiedConnection struct {
	net.Conn
	ProxiedIP net.IP
	Config    ListenerConfig
}

// ReloadableListener is a wrapper for net.Listener that allows reloading
// of config data for postprocessing connections (TLS, PROXY protocol, etc.)
type ReloadableListener struct {
	// TODO: make this lock-free
	sync.Mutex
	realListener net.Listener
	config       ListenerConfig
	isClosed     bool
}

func NewReloadableListener(realListener net.Listener, config ListenerConfig) *ReloadableListener {
	return &ReloadableListener{
		realListener: realListener,
		config:       config,
	}
}

func (rl *ReloadableListener) Reload(config ListenerConfig) {
	rl.Lock()
	rl.config = config
	rl.Unlock()
}

func (rl *ReloadableListener) Accept() (conn net.Conn, err error) {
	conn, err = rl.realListener.Accept()

	rl.Lock()
	config := rl.config
	isClosed := rl.isClosed
	rl.Unlock()

	if isClosed {
		if err == nil {
			conn.Close()
		}
		err = ErrNetClosing
	}
	if err != nil {
		return nil, err
	}

	var proxiedIP net.IP
	if config.RequireProxy {
		// this will occur synchronously on the goroutine calling Accept(),
		// but that's OK because this listener *requires* a PROXY line,
		// therefore it must be used with proxies that always send the line
		// and we won't get slowloris'ed waiting for the client response
		proxyLine := readRawProxyLine(conn, config.ProxyDeadline)
		proxiedIP, err = ParseProxyLine(proxyLine)
		if err != nil {
			conn.Close()
			return nil, err
		}
	}

	if config.TLSConfig != nil {
		conn = tls.Server(conn, config.TLSConfig)
	}

	return &ProxiedConnection{
		Conn:      conn,
		ProxiedIP: proxiedIP,
		Config:    config,
	}, nil
}

func (rl *ReloadableListener) Close() error {
	rl.Lock()
	rl.isClosed = true
	rl.Unlock()

	return rl.realListener.Close()
}

func (rl *ReloadableListener) Addr() net.Addr {
	return rl.realListener.Addr()
}
