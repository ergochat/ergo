package irc

import (
	"bufio"
	"io"
	"log"
	"net"
	"strings"
)

const (
	R   = '→'
	W   = '←'
	EOF = ""
)

type Socket struct {
	closed bool
	conn   net.Conn
	read   chan string
	reader *bufio.Reader
	writer *bufio.Writer
}

func NewSocket(conn net.Conn) *Socket {
	socket := &Socket{
		conn:   conn,
		read:   make(chan string),
		reader: bufio.NewReader(conn),
		writer: bufio.NewWriter(conn),
	}

	go socket.readLines()

	return socket
}

func (socket *Socket) String() string {
	return socket.conn.RemoteAddr().String()
}

func (socket *Socket) Close() {
	if socket.closed {
		return
	}
	socket.closed = true
	socket.conn.Close()
	if DEBUG_NET {
		log.Printf("%s closed", socket)
	}
}

func (socket *Socket) readLines() {
	for {
		line, err := socket.reader.ReadString('\n')
		if socket.isError(err, R) {
			break
		}

		line = strings.TrimRight(line, "\r\n")
		if len(line) == 0 {
			continue
		}
		if DEBUG_NET {
			log.Printf("%s → %s", socket, line)
		}
		socket.read <- line
	}
	close(socket.read)
}

func (socket *Socket) Read() <-chan string {
	return socket.read
}

func (socket *Socket) Write(lines ...string) (err error) {
	if socket.closed {
		return io.EOF
	}
	for _, line := range lines {
		err = socket.WriteLine(line)
		if err != nil {
			break
		}
	}
	return
}

func (socket *Socket) WriteLine(line string) (err error) {
	if _, err = socket.writer.WriteString(line); socket.isError(err, W) {
		return
	}

	if _, err = socket.writer.WriteString(CRLF); socket.isError(err, W) {
		return
	}

	if err = socket.writer.Flush(); socket.isError(err, W) {
		return
	}

	if DEBUG_NET {
		log.Printf("%s ← %s", socket, line)
	}
	return
}

func (socket *Socket) isError(err error, dir rune) bool {
	if err != nil {
		if DEBUG_NET && (err != io.EOF) {
			log.Printf("%s %c error: %s", socket, dir, err)
		}
		return true
	}
	return false
}
