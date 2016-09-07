// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
)

var (
	errNotTLS      = errors.New("Not a TLS connection")
	errNoPeerCerts = errors.New("Client did not provide a certificate")
)

// Socket represents an IRC socket.
type Socket struct {
	Closed bool
	conn   net.Conn
	reader *bufio.Reader
}

// NewSocket returns a new Socket.
func NewSocket(conn net.Conn) Socket {
	return Socket{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

// Close stops a Socket from being able to send/receive any more data.
func (socket *Socket) Close() {
	if socket.Closed {
		return
	}
	socket.Closed = true
	socket.conn.Close()
}

// CertFP returns the fingerprint of the certificate provided by the client.
func (socket *Socket) CertFP() (string, error) {
	var tlsConn, isTLS = socket.conn.(*tls.Conn)
	if !isTLS {
		return "", errNotTLS
	}

	// ensure handehake is performed
	tlsConn.Handshake()

	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) < 1 {
		return "", errNoPeerCerts
	}

	rawCert := sha256.Sum256(peerCerts[0].Raw)
	fingerprint := hex.EncodeToString(rawCert[:])

	return fingerprint, nil
}

// Read returns a single IRC line from a Socket.
func (socket *Socket) Read() (string, error) {
	if socket.Closed {
		return "", io.EOF
	}

	lineBytes, err := socket.reader.ReadBytes('\n')

	// convert bytes to string
	line := string(lineBytes[:])

	// read last message properly (such as ERROR/QUIT/etc), just fail next reads/writes
	if err == io.EOF {
		socket.Close()
	}

	if err == io.EOF && strings.TrimSpace(line) != "" {
		// don't do anything
	} else if err != nil {
		return "", err
	}

	return strings.TrimRight(line, "\r\n"), nil
}

// Write sends the given string out of Socket.
func (socket *Socket) Write(data string) error {
	if socket.Closed {
		return io.EOF
	}

	// write data
	_, err := socket.conn.Write([]byte(data))
	if err != nil {
		socket.Close()
		return err
	}
	return nil
}

// WriteLine writes the given line out of Socket.
func (socket *Socket) WriteLine(line string) error {
	return socket.Write(line + "\r\n")
}
