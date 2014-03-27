package irc

import (
	"bufio"
	"io"
	"net"
	"strings"
)

const (
	R   = '→'
	W   = '←'
	EOF = ""
)

type Socket struct {
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
}

func NewSocket(conn net.Conn, commands chan<- Command) *Socket {
	socket := &Socket{
		conn:   conn,
		reader: bufio.NewReader(conn),
		writer: bufio.NewWriter(conn),
	}

	go socket.readLines(commands)

	return socket
}

func (socket *Socket) String() string {
	return socket.conn.RemoteAddr().String()
}

func (socket *Socket) Close() {
	socket.conn.Close()
	Log.debug.Printf("%s closed", socket)
}

func (socket *Socket) readLines(commands chan<- Command) {
	for {
		line, err := socket.reader.ReadString('\n')
		if socket.isError(err, R) {
			break
		}
		line = strings.TrimRight(line, CRLF)
		if len(line) == 0 {
			continue
		}
		Log.debug.Printf("%s → %s", socket, line)

		msg, err := ParseCommand(line)
		if err != nil {
			// TODO error messaging to client
			continue
		}
		commands <- msg
	}

	close(commands)
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
