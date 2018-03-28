// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	handshakeTimeout, _ = time.ParseDuration("5s")
)

// Socket represents an IRC socket.
type Socket struct {
	conn   net.Conn
	reader *bufio.Reader

	MaxReadQBytes int
	MaxSendQBytes uint64

	// this is only touched by the Read function, which is called in a single-
	// threaded manner, so no mutex needed
	readBuffer []byte

	closed      bool
	closedMutex sync.Mutex

	finalData      string // what to send when we die
	finalDataMutex sync.Mutex

	lineToSendExists chan bool
	linesToSend      []string
	linesToSendMutex sync.Mutex
}

// NewSocket returns a new Socket.
func NewSocket(conn net.Conn, maxReadQBytes int, maxSendQBytes uint64) Socket {
	return Socket{
		conn:             conn,
		reader:           bufio.NewReader(conn),
		MaxReadQBytes:    maxReadQBytes,
		MaxSendQBytes:    maxSendQBytes,
		lineToSendExists: make(chan bool),
	}
}

// Close stops a Socket from being able to send/receive any more data.
func (socket *Socket) Close() {
	socket.closedMutex.Lock()
	defer socket.closedMutex.Unlock()
	if socket.closed {
		return
	}
	socket.closed = true

	// force close loop to happen if it hasn't already
	go socket.timedFillLineToSendExists(200 * time.Millisecond)
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

	var err error

	for {
		var newByte byte
		newByte, err = socket.reader.ReadByte()
		socket.readBuffer = append(socket.readBuffer, newByte)

		// read last message properly (such as ERROR/QUIT/etc), just fail next reads/writes
		if err == io.EOF {
			socket.Close()
			break
		} else if err != nil {
			// just fail out, can't handle random other errors
			socket.Close()
			break
		}

		// we've got a new line!
		if newByte == '\n' {
			break
		}

		// max line len is too large, fail out, just fail out
		if socket.MaxReadQBytes < len(socket.readBuffer) {
			socket.SetFinalData("\r\nERROR :ReadQ Exceeded\r\n")
			socket.Close()
			err = errReadQ
			break
		}
	}

	// convert bytes to string
	line := string(socket.readBuffer[:])
	socket.readBuffer = []byte{}

	if err == io.EOF && strings.TrimSpace(line) != "" {
		// don't do anything
	} else if err != nil {
		return "", err
	}

	return strings.TrimRight(line, "\r\n"), nil
}

// Write sends the given string out of Socket.
func (socket *Socket) Write(data string) error {
	if socket.IsClosed() {
		return io.EOF
	}

	socket.linesToSendMutex.Lock()
	socket.linesToSend = append(socket.linesToSend, data)
	socket.linesToSendMutex.Unlock()

	go socket.timedFillLineToSendExists(15 * time.Second)

	return nil
}

// timedFillLineToSendExists either sends the note or times out.
func (socket *Socket) timedFillLineToSendExists(duration time.Duration) {
	lineToSendTimeout := time.NewTimer(duration)
	defer lineToSendTimeout.Stop()
	select {
	case socket.lineToSendExists <- true:
		// passed data successfully
	case <-lineToSendTimeout.C:
		// timed out send
	}
}

// SetFinalData sets the final data to send when the SocketWriter closes.
func (socket *Socket) SetFinalData(data string) {
	socket.finalDataMutex.Lock()
	if socket.finalData == "" {
		socket.finalData = data
	}
	socket.finalDataMutex.Unlock()
}

// IsClosed returns whether the socket is closed.
func (socket *Socket) IsClosed() bool {
	socket.closedMutex.Lock()
	defer socket.closedMutex.Unlock()
	return socket.closed
}

// RunSocketWriter starts writing messages to the outgoing socket.
func (socket *Socket) RunSocketWriter() {
	for {
		// wait for new lines
		select {
		case <-socket.lineToSendExists:
			socket.linesToSendMutex.Lock()

			// check if we're closed
			if socket.IsClosed() {
				socket.linesToSendMutex.Unlock()
				break
			}

			// check whether new lines actually exist or not
			if len(socket.linesToSend) < 1 {
				socket.linesToSendMutex.Unlock()
				continue
			}

			// check sendq
			var sendQBytes uint64
			for _, line := range socket.linesToSend {
				sendQBytes += uint64(len(line))
				if socket.MaxSendQBytes < sendQBytes {
					// don't unlock mutex because this break is just to escape this for loop
					break
				}
			}
			if socket.MaxSendQBytes < sendQBytes {
				socket.SetFinalData("\r\nERROR :SendQ Exceeded\r\n")
				socket.linesToSendMutex.Unlock()
				break
			}

			// get all existing data
			data := strings.Join(socket.linesToSend, "")
			socket.linesToSend = []string{}

			socket.linesToSendMutex.Unlock()

			// write data
			if 0 < len(data) {
				_, err := socket.conn.Write([]byte(data))
				if err != nil {
					break
				}
			}
		}
		if socket.IsClosed() {
			// error out or we've been closed
			break
		}
	}
	// force closure of socket
	socket.closedMutex.Lock()
	if !socket.closed {
		socket.closed = true
	}
	socket.closedMutex.Unlock()

	// write error lines
	socket.finalDataMutex.Lock()
	if 0 < len(socket.finalData) {
		socket.conn.Write([]byte(socket.finalData))
	}
	socket.finalDataMutex.Unlock()

	// close the connection
	socket.conn.Close()

	// empty the lineToSendExists channel
	for 0 < len(socket.lineToSendExists) {
		<-socket.lineToSendExists
	}
}

// WriteLine writes the given line out of Socket.
func (socket *Socket) WriteLine(line string) error {
	return socket.Write(line + "\r\n")
}
