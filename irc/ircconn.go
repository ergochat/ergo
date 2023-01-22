// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package irc

import (
	"bytes"
	"io"
	"net"
	"unicode/utf8"

	"github.com/ergochat/irc-go/ircmsg"
	"github.com/ergochat/irc-go/ircreader"
	"github.com/gorilla/websocket"

	"github.com/ergochat/ergo/irc/utils"
)

const (
	initialBufferSize = 1024
)

var (
	crlf = []byte{'\r', '\n'}
)

// maximum total length, in bytes, of a single IRC message:
func maxReadQBytes() int {
	return ircmsg.MaxlenTagsFromClient + MaxLineLen + 1024
}

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
	// this returns an IRC line, possibly terminated with CRLF, LF, or nothing:
	ReadLine() (line []byte, err error)

	Close() error
}

// IRCStreamConn is an IRCConn over a regular stream connection.
type IRCStreamConn struct {
	conn *utils.WrappedConn

	reader ircreader.Reader
}

func NewIRCStreamConn(conn *utils.WrappedConn) *IRCStreamConn {
	var c IRCStreamConn
	c.conn = conn
	c.reader.Initialize(conn.Conn, initialBufferSize, maxReadQBytes())
	return &c
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

func (cc *IRCStreamConn) ReadLine() ([]byte, error) {
	line, err := cc.reader.ReadLine()
	if err != nil {
		return nil, err
	} else if globalUtf8EnforcementSetting && !utf8.Valid(line) {
		return line, errInvalidUtf8
	} else {
		return line, nil
	}
}

func (cc *IRCStreamConn) Close() (err error) {
	return cc.conn.Close()
}

// IRCWSConn is an IRCConn over a websocket.
type IRCWSConn struct {
	conn   *websocket.Conn
	buf    []byte
	binary bool
}

func NewIRCWSConn(conn *websocket.Conn) *IRCWSConn {
	return &IRCWSConn{
		conn:   conn,
		binary: conn.Subprotocol() == "binary.ircv3.net",
		buf:    make([]byte, maxReadQBytes()),
	}
}

func (wc *IRCWSConn) UnderlyingConn() *utils.WrappedConn {
	// just assume that the type is OK
	wConn, _ := wc.conn.UnderlyingConn().(*utils.WrappedConn)
	return wConn
}

func (wc *IRCWSConn) WriteLine(buf []byte) (err error) {
	buf = bytes.TrimSuffix(buf, crlf)
	// #1483: if we have websockets at all, then we're enforcing utf8
	messageType := websocket.TextMessage
	if wc.binary {
		messageType = websocket.BinaryMessage
	}
	return wc.conn.WriteMessage(messageType, buf)
}

func (wc *IRCWSConn) WriteLines(buffers [][]byte) (err error) {
	for _, buf := range buffers {
		err = wc.WriteLine(buf)
		if err != nil {
			return
		}
	}
	return
}

func (wc *IRCWSConn) ReadLine() (line []byte, err error) {
	messageType, reader, err := wc.conn.NextReader()
	switch err {
	case nil:
		// OK
	case websocket.ErrReadLimit:
		return line, ircreader.ErrReadQ
	default:
		return line, err
	}

	n, err := io.ReadFull(reader, wc.buf)
	line = wc.buf[:n]
	switch err {
	case io.ErrUnexpectedEOF, io.EOF:
		// these are OK. io.ErrUnexpectedEOF is the good case:
		// it means we read the full message and it consumed less than the full wc.buf
		if messageType == websocket.BinaryMessage && !utf8.Valid(line) {
			return line, errInvalidUtf8
		}
		return line, nil
	case nil, websocket.ErrReadLimit:
		// nil means we filled wc.buf without exhausting the reader:
		return line, ircreader.ErrReadQ
	default:
		return line, err
	}
}

func (wc *IRCWSConn) Close() (err error) {
	return wc.conn.Close()
}
