// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
	// "a 108-byte buffer is always enough to store all the line and a trailing zero
	// for string processing."
	maxProxyLineLenV1 = 107
)

// XXX implement net.Error with a Temporary() method that returns true;
// otherwise, ErrBadProxyLine will cause (*http.Server).Serve() to exit
type proxyLineError struct{}

func (p *proxyLineError) Error() string {
	return "invalid PROXY line"
}

func (p *proxyLineError) Timeout() bool {
	return false
}

func (p *proxyLineError) Temporary() bool {
	return true
}

var (
	ErrBadProxyLine error = &proxyLineError{}
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
	HideSTS   bool
}

// read a PROXY header (either v1 or v2), ensuring we don't read anything beyond
// the header into a buffer (this would break the TLS handshake)
func readRawProxyLine(conn net.Conn, deadline time.Duration) (result []byte, err error) {
	// normally this is covered by ping timeouts, but we're doing this outside
	// of the normal client goroutine:
	conn.SetDeadline(time.Now().Add(deadline))
	defer conn.SetDeadline(time.Time{})

	// read the first 16 bytes of the proxy header
	buf := make([]byte, 16, maxProxyLineLenV1)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return
	}

	switch buf[0] {
	case 'P':
		// PROXY v1: starts with "PROXY"
		return readRawProxyLineV1(conn, buf)
	case '\r':
		// PROXY v2: starts with "\r\n\r\n"
		return readRawProxyLineV2(conn, buf)
	default:
		return nil, ErrBadProxyLine
	}
}

func readRawProxyLineV1(conn net.Conn, buf []byte) (result []byte, err error) {
	for {
		i := len(buf)
		if i >= maxProxyLineLenV1 {
			return nil, ErrBadProxyLine // did not find \r\n, fail
		}
		// prepare a single byte of free space, then read into it
		buf = buf[0 : i+1]
		_, err = io.ReadFull(conn, buf[i:])
		if err != nil {
			return nil, err
		}
		if buf[i] == '\n' {
			return buf, nil
		}
	}
}

func readRawProxyLineV2(conn net.Conn, buf []byte) (result []byte, err error) {
	// "The 15th and 16th bytes is the address length in bytes in network endian order."
	addrLen := int(binary.BigEndian.Uint16(buf[14:16]))
	if addrLen == 0 {
		return buf[0:16], nil
	} else if addrLen <= cap(buf)-16 {
		buf = buf[0 : 16+addrLen]
	} else {
		// proxy source is unix domain, we don't really handle this
		buf2 := make([]byte, 16+addrLen)
		copy(buf2[0:16], buf[0:16])
		buf = buf2
	}
	_, err = io.ReadFull(conn, buf[16:16+addrLen])
	if err != nil {
		return
	}
	return buf[0 : 16+addrLen], nil
}

// ParseProxyLine parses a PROXY protocol (v1 or v2) line and returns the remote IP.
func ParseProxyLine(line []byte) (ip net.IP, err error) {
	if len(line) == 0 {
		return nil, ErrBadProxyLine
	}
	switch line[0] {
	case 'P':
		return ParseProxyLineV1(string(line))
	case '\r':
		return parseProxyLineV2(line)
	default:
		return nil, ErrBadProxyLine
	}
}

// ParseProxyLineV1 parses a PROXY protocol (v1) line and returns the remote IP.
func ParseProxyLineV1(line string) (ip net.IP, err error) {
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

func parseProxyLineV2(line []byte) (ip net.IP, err error) {
	if len(line) < 16 {
		return nil, ErrBadProxyLine
	}
	// this doesn't allocate
	if string(line[:12]) != "\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a" {
		return nil, ErrBadProxyLine
	}
	// "The next byte (the 13th one) is the protocol version and command."
	versionCmd := line[12]
	// "The highest four bits contains the version [....] it must always be sent as \x2"
	if (versionCmd >> 4) != 2 {
		return nil, ErrBadProxyLine
	}
	// "The lowest four bits represents the command"
	switch versionCmd & 0x0f {
	case 0:
		return nil, nil // LOCAL command
	case 1:
		// PROXY command, continue below
	default:
		// "Receivers must drop connections presenting unexpected values here"
		return nil, ErrBadProxyLine
	}

	var addrLen int
	// "The 14th byte contains the transport protocol and address family."
	protoAddr := line[13]
	// "The highest 4 bits contain the address family"
	switch protoAddr >> 4 {
	case 1:
		addrLen = 4 // AF_INET
	case 2:
		addrLen = 16 // AF_INET6
	default:
		return nil, nil // AF_UNSPEC or AF_UNIX, either way there's no IP address
	}

	// header, source and destination address, two 16-bit port numbers:
	expectedLen := 16 + 2*addrLen + 4
	if len(line) < expectedLen {
		return nil, ErrBadProxyLine
	}

	// "Starting from the 17th byte, addresses are presented in network byte order.
	//  The address order is always the same :
	//    - source layer 3 address in network byte order [...]"
	if addrLen == 4 {
		ip = net.IP(line[16 : 16+addrLen]).To16()
	} else {
		ip = make(net.IP, addrLen)
		copy(ip, line[16:16+addrLen])
	}
	return ip, nil
}

// / WrappedConn is a net.Conn with some additional data stapled to it;
// the proxied IP, if one was read via the PROXY protocol, and the listener
// configuration.
type WrappedConn struct {
	net.Conn
	ProxiedIP net.IP
	Config    ListenerConfig
	// Secure indicates whether we believe the connection between us and the client
	// was secure against interception and modification (including all proxies):
	Secure bool
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
		err = net.ErrClosed
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
		proxyLine, err := readRawProxyLine(conn, config.ProxyDeadline)
		if err == nil {
			proxiedIP, err = ParseProxyLine(proxyLine)
		}
		if err != nil {
			conn.Close()
			return nil, err
		}
	}

	if config.TLSConfig != nil {
		conn = tls.Server(conn, config.TLSConfig)
	}

	return &WrappedConn{
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
