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
// it doesn't expose the net.Conn, io.Reader, or io.Writer interfaces
// because websockets are message-oriented, not stream-oriented, and
// therefore this abstraction is message-oriented as well.
type IRCConn interface {
	UnderlyingConn() *utils.WrappedConn

	// these take an IRC line or lines, correctly terminated with CRLF:
	WriteLine([]byte) error
	WriteLines([][]byte) error
	// this returns an IRC line without the terminating CRLF:
	ReadLine() (line []byte, err error)

	Close() error
}

// IRCStreamConn is an IRCConn over a regular stream connection.
type IRCStreamConn struct {
	conn   *utils.WrappedConn
	reader *bufio.Reader
}

func NewIRCStreamConn(conn *utils.WrappedConn) *IRCStreamConn {
	return &IRCStreamConn{
		conn: conn,
	}
}

func (cc *IRCStreamConn) UnderlyingConn() *utils.WrappedConn {
	return cc.conn
}

func (cc *IRCStreamConn) WriteLine(buf []byte) (err error) {
	_, err = cc.conn.Write(buf)
	return
}

func (cc *IRCStreamConn) WriteLines(buffers [][]byte) (err error) {
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
	if globalUtf8EnforcementSetting && !utf8.Valid(line) {
		err = errInvalidUtf8
	}
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

func (wc IRCWSConn) UnderlyingConn() *utils.WrappedConn {
	// just assume that the type is OK
	wConn, _ := wc.conn.UnderlyingConn().(*utils.WrappedConn)
	return wConn
}

func (wc IRCWSConn) WriteLine(buf []byte) (err error) {
	buf = bytes.TrimSuffix(buf, crlf)
	if !globalUtf8EnforcementSetting && !utf8.Valid(buf) {
		// there's not much we can do about this;
		// silently drop the message
		return nil
	}
	return wc.conn.WriteMessage(websocket.TextMessage, buf)
}

func (wc IRCWSConn) WriteLines(buffers [][]byte) (err error) {
	for _, buf := range buffers {
		err = wc.WriteLine(buf)
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
