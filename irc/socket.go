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
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	errNotTLS           = errors.New("Not a TLS connection")
	errNoPeerCerts      = errors.New("Client did not provide a certificate")
	handshakeTimeout, _ = time.ParseDuration("5s")
)

// Socket represents an IRC socket.
type Socket struct {
	Closed bool
	conn   net.Conn
	reader *bufio.Reader

	lineToSendExists chan bool
	linesToSend      []string
	linesToSendMutex sync.Mutex
}

// NewSocket returns a new Socket.
func NewSocket(conn net.Conn) Socket {
	return Socket{
		conn:             conn,
		reader:           bufio.NewReader(conn),
		lineToSendExists: make(chan bool),
	}
}

// Close stops a Socket from being able to send/receive any more data.
func (socket *Socket) Close() {
	socket.Closed = true
	// socket will close once all data has been sent
}

// CertFP returns the fingerprint of the certificate provided by the client.
func (socket *Socket) CertFP() (string, error) {
	var tlsConn, isTLS = socket.conn.(*tls.Conn)
	if !isTLS {
		return "", errNotTLS
	}

	// ensure handehake is performed, and timeout after a few seconds
	tlsConn.SetDeadline(time.Now().Add(handshakeTimeout))
	err := tlsConn.Handshake()
	tlsConn.SetDeadline(time.Time{})

	if err != nil {
		return "", err
	}

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

	socket.linesToSendMutex.Lock()
	socket.linesToSend = append(socket.linesToSend, data)
	socket.linesToSendMutex.Unlock()
	go socket.fillLineToSendExists()

	return nil
}

// fillLineToSendExists only exists because you can't goroutine single statements.
func (socket *Socket) fillLineToSendExists() {
	socket.lineToSendExists <- true
}

// RunSocketWriter starts writing messages to the outgoing socket.
func (socket *Socket) RunSocketWriter() {
	var errOut bool
	for {
		// wait for new lines
		select {
		case <-socket.lineToSendExists:
			socket.linesToSendMutex.Lock()

			// get data
			data := socket.linesToSend[0]
			if len(socket.linesToSend) > 1 {
				socket.linesToSend = socket.linesToSend[1:]
			} else {
				socket.linesToSend = []string{}
			}

			// write data
			_, err := socket.conn.Write([]byte(data))
			if err != nil {
				errOut = true
				fmt.Println(err.Error())
				break
			}
			socket.linesToSendMutex.Unlock()
		}
		if errOut {
			// error out, bad stuff happened
			break
		}
	}
	//TODO(dan): empty socket.lineToSendExists queue
	socket.conn.Close()
	if !socket.Closed {
		socket.Closed = true
	}
}

// WriteLine writes the given line out of Socket.
func (socket *Socket) WriteLine(line string) error {
	return socket.Write(line + "\r\n")
}
