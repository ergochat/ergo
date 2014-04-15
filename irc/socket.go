package irc

import (
	"bufio"
	"io"
	"net"
)

const (
	R = '→'
	W = '←'
)

type Socket struct {
	conn    net.Conn
	scanner *bufio.Scanner
	writer  *bufio.Writer
}

func NewSocket(conn net.Conn) *Socket {
	return &Socket{
		conn:    conn,
		scanner: bufio.NewScanner(conn),
		writer:  bufio.NewWriter(conn),
	}
}

func (socket *Socket) String() string {
	return socket.conn.RemoteAddr().String()
}

func (socket *Socket) Close() {
	socket.conn.Close()
	Log.debug.Printf("%s closed", socket)
}

func (socket *Socket) Read() (line string, err error) {
	for socket.scanner.Scan() {
		line = socket.scanner.Text()
		if len(line) == 0 {
			continue
		}
		Log.debug.Printf("%s → %s", socket, line)
		return
	}

	err = socket.scanner.Err()
	socket.isError(err, R)
	if err == nil {
		err = io.EOF
	}
	return
}

func (socket *Socket) Write(line string) (err error) {
	if _, err = socket.writer.WriteString(line); socket.isError(err, W) {
		return
	}

	if _, err = socket.writer.WriteString(CRLF); socket.isError(err, W) {
		return
	}

	if err = socket.writer.Flush(); socket.isError(err, W) {
		return
	}

	Log.debug.Printf("%s ← %s", socket, line)
	return
}

func (socket *Socket) isError(err error, dir rune) bool {
	if err != nil {
		if err != io.EOF {
			Log.debug.Printf("%s %c error: %s", socket, dir, err)
		}
		return true
	}
	return false
}
