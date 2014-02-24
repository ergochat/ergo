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
	client *Client
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
}

func NewSocket(conn net.Conn, client *Client, commands chan<- Command) *Socket {
	socket := &Socket{
		conn:   conn,
		reader: bufio.NewReader(conn),
		client: client,
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
	if DEBUG_NET {
		log.Printf("%s closed", socket)
	}
}

func (socket *Socket) readLines(commands chan<- Command) {
	hostnameLookup := &ProxyCommand{
		hostname: AddrLookupHostname(socket.conn.RemoteAddr()),
	}
	hostnameLookup.SetClient(socket.client)
	commands <- hostnameLookup

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

		msg, err := ParseCommand(line)
		if err != nil {
			// TODO error messaging to client
			continue
		}
		msg.SetClient(socket.client)
		commands <- msg
	}

	msg := &QuitCommand{
		message: "connection closed",
	}
	msg.SetClient(socket.client)
	commands <- msg
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
