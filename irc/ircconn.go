package irc

import (
	"bufio"
	"bytes"
	"net"
	"unicode/utf8"

	"github.com/gorilla/websocket"
	"github.com/goshuirc/irc-go/ircmsg"

	"github.com/oragono/oragono/irc/utils"
)

const (
	maxReadQBytes = ircmsg.MaxlenTagsFromClient + 512 + 1024
)

var (
	crlf = []byte{'\r', '\n'}
)

// IRCConn abstracts away the distinction between a regular
// net.Conn (which includes both raw TCP and TLS) and a websocket.
// it doesn't expose Read and Write because websockets are message-oriented,
// not stream-oriented.
type IRCConn interface {
	UnderlyingConn() *utils.ProxiedConnection

	Write([]byte) error
	WriteBuffers([][]byte) error
	ReadLine() (line []byte, err error)

	Close() error
}

// IRCStreamConn is an IRCConn over a regular stream connection.
type IRCStreamConn struct {
	conn   *utils.ProxiedConnection
	reader *bufio.Reader
}

func NewIRCStreamConn(conn *utils.ProxiedConnection) *IRCStreamConn {
	return &IRCStreamConn{
		conn: conn,
	}
}

func (cc *IRCStreamConn) UnderlyingConn() *utils.ProxiedConnection {
	return cc.conn
}

func (cc *IRCStreamConn) Write(buf []byte) (err error) {
	_, err = cc.conn.Write(buf)
	return
}

func (cc *IRCStreamConn) WriteBuffers(buffers [][]byte) (err error) {
	// on Linux, with a plaintext TCP or Unix domain socket,
	// the Go runtime will optimize this into a single writev(2) call:
	_, err = (*net.Buffers)(&buffers).WriteTo(cc.conn)
	return
}

func (cc *IRCStreamConn) ReadLine() (line []byte, err error) {
	// lazy initialize the reader in case the IP is banned
	if cc.reader == nil {
		cc.reader = bufio.NewReaderSize(cc.conn, maxReadQBytes)
	}

	var isPrefix bool
	line, isPrefix, err = cc.reader.ReadLine()
	if isPrefix {
		return nil, errReadQ
	}
	line = bytes.TrimSuffix(line, crlf)
	return
}

func (cc *IRCStreamConn) Close() (err error) {
	return cc.conn.Close()
}

// IRCWSConn is an IRCConn over a websocket.
type IRCWSConn struct {
	conn *websocket.Conn
}

func NewIRCWSConn(conn *websocket.Conn) IRCWSConn {
	return IRCWSConn{conn: conn}
}

func (wc IRCWSConn) UnderlyingConn() *utils.ProxiedConnection {
	pConn, ok := wc.conn.UnderlyingConn().(*utils.ProxiedConnection)
	if ok {
		return pConn
	} else {
		// this can't happen
		return nil
	}
}

func (wc IRCWSConn) Write(buf []byte) (err error) {
	buf = bytes.TrimSuffix(buf, crlf)
	// there's not much we can do about this;
	// silently drop the message
	if !utf8.Valid(buf) {
		return nil
	}
	return wc.conn.WriteMessage(websocket.TextMessage, buf)
}

func (wc IRCWSConn) WriteBuffers(buffers [][]byte) (err error) {
	for _, buf := range buffers {
		err = wc.Write(buf)
		if err != nil {
			return
		}
	}
	return
}

func (wc IRCWSConn) ReadLine() (line []byte, err error) {
	for {
		var messageType int
		messageType, line, err = wc.conn.ReadMessage()
		// on empty message or non-text message, try again, block if necessary
		if err != nil || (messageType == websocket.TextMessage && len(line) != 0) {
			return
		}
	}
}

func (wc IRCWSConn) Close() (err error) {
	return wc.conn.Close()
}
