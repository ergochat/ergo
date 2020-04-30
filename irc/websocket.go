package irc

import (
	"bytes"
	"errors"
	"github.com/gorilla/websocket"
	"net/http"
	"time"
	"unicode/utf8"
)

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  2 * 1024,
	WriteBufferSize: 2 * 1024,
	// If a WS session contains sensitive information, and you choose to use
	// cookies for authentication (during the HTTP(S) upgrade request), then
	// you should check that Origin is a domain under your control. If it
	// isn't, then it is possible for users of your site, visiting a naughty
	// Origin, to have a WS opened using their credentials. See
	// http://www.christian-schneider.net/CrossSiteWebSocketHijacking.html#main.
	// We don't care about Origin because the (IRC) authentication is contained
	// in the WS stream -- the WS session is not privileged when it is opened.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// WSContainer wraps a WebSocket connection so that it implements net.Conn
// entirely.
type WSContainer struct {
	*websocket.Conn
}

func (ws WSContainer) Read(b []byte) (n int, err error) {
	var messageType int
	var bytes []byte

	for {
		messageType, bytes, err = ws.ReadMessage()
		if messageType == websocket.TextMessage {
			n = copy(b, bytes)
			return
		}
		if len(bytes) == 0 {
			return 0, nil
		}
		// Throw other kind of messages away.
	}
	// We don't want to return (0, nil) here because that would mean the
	// connection is closed (Read calls must block until data is received).
}

func (ws WSContainer) Write(b []byte) (n int, err error) {
	if !utf8.Valid(b) {
		return 0, errors.New("outgoing WebSocket message isn't valid UTF-8")
	}

	b = bytes.TrimSuffix(b, []byte("\r\n"))
	n = len(b)
	err = ws.WriteMessage(websocket.TextMessage, b)
	return
}

// SetDeadline is part of the net.Conn interface.
func (ws WSContainer) SetDeadline(t time.Time) (err error) {
	err = ws.SetWriteDeadline(t)
	if err != nil {
		return
	}
	err = ws.SetReadDeadline(t)
	return
}
