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

	// this is a trylock enforcing that only one goroutine can write to `conn` at a time
	writerSlotOpen chan bool

	buffer        []byte
	closed        bool
	sendQExceeded bool
	finalData     string // what to send when we die
	finalized     bool
}

// NewSocket returns a new Socket.
func NewSocket(conn net.Conn, maxReadQBytes int, maxSendQBytes int) *Socket {
	result := Socket{
		conn:           conn,
		reader:         bufio.NewReaderSize(conn, maxReadQBytes),
		maxSendQBytes:  maxSendQBytes,
		writerSlotOpen: make(chan bool, 1),
	}
	result.writerSlotOpen <- true
	return &result
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

// Write sends the given string out of Socket. Requirements:
// 1. MUST NOT block for macroscopic amounts of time
// 2. MUST NOT reorder messages
// 3. MUST provide mutual exclusion for socket.conn.Write
// 4. SHOULD NOT tie up additional goroutines, beyond the one blocked on socket.conn.Write
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

// wakeWriter starts the goroutine that actually performs the write, without blocking
func (socket *Socket) wakeWriter() {
	// attempt to acquire the trylock
	select {
	case <-socket.writerSlotOpen:
		// acquired the trylock; send() will release it
		go socket.send()
	default:
		// failed to acquire; the holder will check for more data after releasing it
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

// is there data to write?
func (socket *Socket) readyToWrite() bool {
	socket.Lock()
	defer socket.Unlock()
	// on the first time observing socket.closed, we still have to write socket.finalData
	return !socket.finalized && (len(socket.buffer) > 0 || socket.closed || socket.sendQExceeded)
}

// send actually writes messages to socket.Conn; it may block
func (socket *Socket) send() {
	for {
		// we are holding the trylock: actually do the write
		socket.performWrite()
		// surrender the trylock, avoiding a race where a write comes in after we've
		// checked readyToWrite() and it returned false, but while we still hold the trylock:
		socket.writerSlotOpen <- true
		// check if more data came in while we held the trylock:
		if !socket.readyToWrite() {
			return
		}
		select {
		case <-socket.writerSlotOpen:
			// got the trylock, loop back around and write
		default:
			// failed to acquire; exit and wait for the holder to observe readyToWrite()
			// after releasing it
			return
		}
	}
}

// write the contents of the buffer, then see if we need to close
func (socket *Socket) performWrite() {
	// retrieve the buffered data, clear the buffer
	socket.Lock()
	buffer := socket.buffer
	socket.buffer = nil
	socket.Unlock()

	_, err := socket.conn.Write(buffer)

	socket.Lock()
	shouldClose := (err != nil) || socket.closed || socket.sendQExceeded
	socket.Unlock()

	if !shouldClose {
		return
	}

	// mark the socket closed (if someone hasn't already), then write error lines
	socket.Lock()
	socket.closed = true
	socket.finalized = true
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
