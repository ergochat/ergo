package irc

import (
	"bytes"
	"errors"
	"io"
	"net"
	"unicode/utf8"

	"github.com/gorilla/websocket"
	"github.com/goshuirc/irc-go/ircmsg"

	"github.com/oragono/oragono/irc/utils"
)

const (
	maxReadQBytes     = ircmsg.MaxlenTagsFromClient + MaxLineLen + 1024
	initialBufferSize = 1024
)

var (
	crlf     = []byte{'\r', '\n'}
	errReadQ = errors.New("ReadQ Exceeded")
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
	// this returns an IRC line, possibly terminated with CRLF, LF, or nothing:
	ReadLine() (line []byte, err error)

	Close() error
}

// IRCStreamConn is an IRCConn over a regular stream connection.
type IRCStreamConn struct {
	conn *utils.WrappedConn

	buf        []byte
	start      int // start of valid (i.e., read but not yet consumed) data in the buffer
	end        int // end of valid data in the buffer
	searchFrom int // start of valid data in the buffer not yet searched for \n
	eof        bool
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

func (cc *IRCStreamConn) ReadLine() ([]byte, error) {
	for {
		// try to find a terminated line in the buffered data already read
		nlidx := bytes.IndexByte(cc.buf[cc.searchFrom:cc.end], '\n')
		if nlidx != -1 {
			// got a complete line
			line := cc.buf[cc.start : cc.searchFrom+nlidx]
			cc.start = cc.searchFrom + nlidx + 1
			cc.searchFrom = cc.start
			if globalUtf8EnforcementSetting && !utf8.Valid(line) {
				return line, errInvalidUtf8
			} else {
				return line, nil
			}
		}

		if cc.start == 0 && len(cc.buf) == maxReadQBytes {
			return nil, errReadQ // out of space, can't expand or slide
		}

		if cc.eof {
			return nil, io.EOF
		}

		if len(cc.buf) < maxReadQBytes && (len(cc.buf)-(cc.end-cc.start) < initialBufferSize/2) {
			// allocate a new buffer, copy any remaining data
			newLen := utils.RoundUpToPowerOfTwo(len(cc.buf) + 1)
			if newLen > maxReadQBytes {
				newLen = maxReadQBytes
			} else if newLen < initialBufferSize {
				newLen = initialBufferSize
			}
			newBuf := make([]byte, newLen)
			copy(newBuf, cc.buf[cc.start:cc.end])
			cc.buf = newBuf
		} else if cc.start != 0 {
			// slide remaining data back to the front of the buffer
			copy(cc.buf, cc.buf[cc.start:cc.end])
		}
		cc.end = cc.end - cc.start
		cc.start = 0

		cc.searchFrom = cc.end
		n, err := cc.conn.Read(cc.buf[cc.end:])
		cc.end += n
		if n != 0 && err == io.EOF {
			// we may have received new \n-terminated lines, try to parse them
			cc.eof = true
		} else if err != nil {
			return nil, err
		}
	}
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
	messageType, line, err := wc.conn.ReadMessage()
	if err == nil {
		if messageType == websocket.TextMessage {
			return line, nil
		} else {
			// for purposes of fakelag, treat non-text message as an empty line
			return nil, nil
		}
	} else if err == websocket.ErrReadLimit {
		return line, errReadQ
	} else {
		return line, err
	}
}

func (wc IRCWSConn) Close() (err error) {
	return wc.conn.Close()
}
