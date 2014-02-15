package irc

import (
	"bufio"
	"io"
	"log"
	"net"
	"strings"
	"sync"
)

type Socket struct {
	closed  bool
	conn    net.Conn
	mutex   *sync.Mutex
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
		mutex:   &sync.Mutex{},
		writer:  bufio.NewWriter(conn),
	}

	go socket.readLines()
	go socket.writeLines()

	return socket
}

func (socket *Socket) String() string {
	return socket.conn.RemoteAddr().String()
}

func (socket *Socket) IsClosed() bool {
	socket.mutex.Lock()
	defer socket.mutex.Unlock()
	return socket.closed
}

func (socket *Socket) Close() {
	if socket.IsClosed() {
		return
	}

	if DEBUG_NET {
		log.Printf("%s closed", socket)
	}

	socket.mutex.Lock()
	socket.closed = true
	socket.conn.Close()
	close(socket.send)
	close(socket.receive)
	socket.mutex.Unlock()
}

func (socket *Socket) Read() <-chan string {
	return socket.receive
}

func (socket *Socket) Write(lines []string) error {
	for _, line := range lines {
		if socket.IsClosed() {
			return io.EOF
		}
		socket.send <- line
	}
	return nil
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
	socket.Close()
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
