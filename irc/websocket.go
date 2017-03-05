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

type WSContainer struct {
	*websocket.Conn
}

func (this WSContainer) Read(msg []byte) (int, error) {
	ty, bytes, err := this.ReadMessage()
	if ty == websocket.TextMessage {
		n := copy(msg, []byte(string(bytes)+"\r\n\r\n"))
		return n, err
	}
	// Binary, and other kinds of messages, are thrown away.
	return 0, nil
}

func (this WSContainer) Write(msg []byte) (int, error) {
	err := this.WriteMessage(websocket.TextMessage, msg)
	return len(msg), err
}

func (this WSContainer) SetDeadline(t time.Time) error {
	if err := this.SetWriteDeadline(t); err != nil {
		return err
	}
	return this.SetReadDeadline(t)
}
