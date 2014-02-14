package irc

import (
	"bufio"
	"io"
	"log"
	"net"
	"strings"
)

type Socket struct {
	closed  bool
	conn    net.Conn
	reader  *bufio.Reader
	writer  *bufio.Writer
	send    chan string
	receive chan string
}

func NewSocket(conn net.Conn) *Socket {
	socket := &Socket{
		conn:    conn,
		reader:  bufio.NewReader(conn),
		receive: make(chan string),
		send:    make(chan string),
		writer:  bufio.NewWriter(conn),
	}

	go socket.readLines()
	go socket.writeLines()

	return socket
}

func (socket *Socket) String() string {
	return socket.conn.RemoteAddr().String()
}

func (socket *Socket) Close() {
	if socket.closed {
		return
	}

	if DEBUG_NET {
		log.Printf("%s closed", socket)
	}

	socket.closed = true
	socket.conn.Close()
	close(socket.send)
	close(socket.receive)
}

func (socket *Socket) Read() <-chan string {
	return socket.receive
}

func (socket *Socket) Write(lines []string) error {
	for _, line := range lines {
		if socket.closed {
			return io.EOF
		}
		socket.send <- line
	}
	return nil
}

func (socket *Socket) readLines() {
	for !socket.closed {
		line, err := socket.reader.ReadString('\n')
		if err != nil {
			if DEBUG_NET {
				log.Printf("%s → error: %s", socket, err)
			}
			break
		}

		line = strings.TrimSpace(line)
		if DEBUG_NET {
			log.Printf("%s → %s", socket, line)
		}

		socket.receive <- line
	}
	socket.Close()
}

func (socket *Socket) writeLines() {
	for line := range socket.send {
		if DEBUG_CLIENT {
			log.Printf("%s ← %s", socket, line)
		}
		if _, err := socket.writer.WriteString(line); socket.maybeLogWriteError(err) {
			break
		}
		if _, err := socket.writer.WriteString(CRLF); socket.maybeLogWriteError(err) {
			break
		}
		if err := socket.writer.Flush(); socket.maybeLogWriteError(err) {
			break
		}
	}
	socket.Close()
}

func (socket *Socket) maybeLogWriteError(err error) bool {
	if err != nil {
		if DEBUG_NET {
			log.Printf("%s ← error: %s", socket, err)
		}
		return true
	}
	return false
}
