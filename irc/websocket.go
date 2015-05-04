package irc

import (
	"github.com/gorilla/websocket"
	"net"
	"net/http"
	"time"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

type WSContainer struct {
	conn *websocket.Conn
}

func (this WSContainer) Close() error {
	return this.conn.Close()
}

func (this WSContainer) LocalAddr() net.Addr {
	return this.conn.LocalAddr()
}

func (this WSContainer) RemoteAddr() net.Addr {
	return this.conn.RemoteAddr()
}

func (this WSContainer) Read(msg []byte) (int, error) {
	_, tmp, err := this.conn.ReadMessage()
	str := (string)(tmp)
	n := copy(msg, ([]byte)(str+CRLF+CRLF))
	return n, err
}

func (this WSContainer) Write(msg []byte) (int, error) {
	err := this.conn.WriteMessage(1, msg)
	return len(msg), err
}

func (this WSContainer) SetDeadline(t time.Time) error {
	err := this.conn.SetWriteDeadline(t)
	err = this.conn.SetReadDeadline(t)
	return err
}

func (this WSContainer) SetReadDeadline(t time.Time) error {
	return this.conn.SetReadDeadline(t)
}

func (this WSContainer) SetWriteDeadline(t time.Time) error {
	return this.conn.SetWriteDeadline(t)
}
