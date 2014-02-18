package irc

import (
	"bufio"
	"log"
	"net"
	"strings"
)

const (
	R = '→'
	W = '←'
)

type Socket struct {
	closed  bool
	conn    net.Conn
	done    chan bool
	reader  *bufio.Reader
	receive chan string
	send    chan string
	writer  *bufio.Writer
}

func NewSocket(conn net.Conn) *Socket {
	socket := &Socket{
		conn:    conn,
		done:    make(chan bool),
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

	socket.closed = true
	socket.done <- true
	close(socket.done)
}

func (socket *Socket) Read() <-chan string {
	return socket.receive
}

func (socket *Socket) Write(lines ...string) {
	for _, line := range lines {
		socket.send <- line
	}
	return
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

		socket.receive <- line
	}

	close(socket.receive)
	if DEBUG_NET {
		log.Printf("%s closed", socket)
	}
}

func (socket *Socket) writeLines() {
	done := false
	for !done {
		select {
		case line := <-socket.send:
			if _, err := socket.writer.WriteString(line); socket.isError(err, W) {
				break
			}
			if _, err := socket.writer.WriteString(CRLF); socket.isError(err, W) {
				break
			}

			if err := socket.writer.Flush(); socket.isError(err, W) {
				break
			}
			if DEBUG_NET {
				log.Printf("%s ← %s", socket, line)
			}

		case done = <-socket.done:
			continue
		}
	}

	if DEBUG_NET {
		log.Printf("%s closing", socket)
	}
	socket.conn.Close()

	for _ = range socket.send {
		// discard lines
	}
}

func (socket *Socket) isError(err error, dir rune) bool {
	if err != nil {
		if DEBUG_NET {
			log.Printf("%s %c error: %s", socket, dir, err)
		}
		return true
	}
	return false
}
