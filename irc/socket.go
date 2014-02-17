package irc

import (
	"bufio"
	"log"
	"net"
	"strings"
)

type Socket struct {
	conn    net.Conn
	reader  *bufio.Reader
	receive chan string
	send    chan string
	writer  *bufio.Writer
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
	socket.conn.Close()
}

func (socket *Socket) Read() <-chan string {
	return socket.receive
}

func (socket *Socket) Write(lines []string) {
	for _, line := range lines {
		socket.send <- line
	}
	return
}

func (socket *Socket) readLines() {
	for {
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
	close(socket.receive)
}

func (socket *Socket) writeLines() {
	for line := range socket.send {
		if DEBUG_NET {
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
