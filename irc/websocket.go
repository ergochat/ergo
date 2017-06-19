// Copyright (c) 2015 Niels Freier
// Copyright (c) 2015 Edmund Huber
// released under the MIT license

package irc

import (
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  2048,
	WriteBufferSize: 2048,
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

// WSContainer holds the websocket.
type WSContainer struct {
	*websocket.Conn
}

// Read reads new incoming messages.
func (ws WSContainer) Read(msg []byte) (int, error) {
	ty, bytes, err := ws.ReadMessage()
	if ty == websocket.TextMessage {
		n := copy(msg, []byte(string(bytes)+"\r\n\r\n"))
		return n, err
	}
	// Binary, and other kinds of messages, are thrown away.
	return 0, nil
}

// Write writes lines out to the websocket.
func (ws WSContainer) Write(msg []byte) (int, error) {
	err := ws.WriteMessage(websocket.TextMessage, msg)
	return len(msg), err
}

// SetDeadline sets the read and write deadline on this websocket.
func (ws WSContainer) SetDeadline(t time.Time) error {
	if err := ws.SetWriteDeadline(t); err != nil {
		return err
	}
	return ws.SetReadDeadline(t)
}
