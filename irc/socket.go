// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
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
	"sync"
	"time"
)

var (
	handshakeTimeout, _ = time.ParseDuration("5s")
	errSendQExceeded    = errors.New("SendQ exceeded")
)

// Socket represents an IRC socket.
type Socket struct {
	sync.Mutex

	conn   net.Conn
	reader *bufio.Reader

	maxSendQBytes int

	// coordination system for asynchronous writes
	buffer           []byte
	lineToSendExists chan bool

	closed        bool
	sendQExceeded bool
	finalData     string // what to send when we die
}

// NewSocket returns a new Socket.
func NewSocket(conn net.Conn, maxReadQBytes int, maxSendQBytes int) Socket {
	return Socket{
		conn:             conn,
		reader:           bufio.NewReaderSize(conn, maxReadQBytes),
		maxSendQBytes:    maxSendQBytes,
		lineToSendExists: make(chan bool, 1),
	}
}

// Close stops a Socket from being able to send/receive any more data.
func (socket *Socket) Close() {
	socket.Lock()
	socket.closed = true
	socket.Unlock()

	socket.wakeWriter()
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
	if socket.IsClosed() {
		return "", io.EOF
	}

	lineBytes, isPrefix, err := socket.reader.ReadLine()
	if isPrefix {
		return "", errReadQ
	}

	// convert bytes to string
	line := string(lineBytes)

	// read last message properly (such as ERROR/QUIT/etc), just fail next reads/writes
	if err == io.EOF {
		socket.Close()
	}

	if err == io.EOF && strings.TrimSpace(line) != "" {
		// don't do anything
	} else if err != nil {
		return "", err
	}

	return line, nil
}

// Write sends the given string out of Socket.
func (socket *Socket) Write(data string) (err error) {
	socket.Lock()
	if socket.closed {
		err = io.EOF
	} else if len(data)+len(socket.buffer) > socket.maxSendQBytes {
		socket.sendQExceeded = true
		err = errSendQExceeded
	} else {
		socket.buffer = append(socket.buffer, data...)
	}
	socket.Unlock()

	socket.wakeWriter()
	return
}

// wakeWriter wakes up the goroutine that actually performs the write, without blocking
func (socket *Socket) wakeWriter() {
	// nonblocking send to the channel, no-op if it's full
	select {
	case socket.lineToSendExists <- true:
	default:
	}
}

// SetFinalData sets the final data to send when the SocketWriter closes.
func (socket *Socket) SetFinalData(data string) {
	socket.Lock()
	defer socket.Unlock()
	socket.finalData = data
}

// IsClosed returns whether the socket is closed.
func (socket *Socket) IsClosed() bool {
	socket.Lock()
	defer socket.Unlock()
	return socket.closed
}

// RunSocketWriter starts writing messages to the outgoing socket.
func (socket *Socket) RunSocketWriter() {
	localBuffer := make([]byte, 0)
	shouldStop := false
	for !shouldStop {
		// wait for new lines
		select {
		case <-socket.lineToSendExists:
			// retrieve the buffered data, clear the buffer
			socket.Lock()
			localBuffer = append(localBuffer, socket.buffer...)
			socket.buffer = socket.buffer[:0]
			socket.Unlock()

			_, err := socket.conn.Write(localBuffer)
			localBuffer = localBuffer[:0]

			socket.Lock()
			shouldStop = (err != nil) || socket.closed || socket.sendQExceeded
			socket.Unlock()
		}
	}

	// mark the socket closed (if someone hasn't already), then write error lines
	socket.Lock()
	socket.closed = true
	finalData := socket.finalData
	if socket.sendQExceeded {
		finalData = "\r\nERROR :SendQ Exceeded\r\n"
	}
	socket.Unlock()
	if finalData != "" {
		socket.conn.Write([]byte(finalData))
	}

	// close the connection
	socket.conn.Close()
}
