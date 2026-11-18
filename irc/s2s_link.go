// Copyright (c) 2026 Ergo Developers
// released under the MIT license

package irc

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ergochat/ergo/irc/utils"
	"github.com/ergochat/irc-go/ircmsg"
)

const (
	s2sSendQueueSize    = 1024
	s2sPingInterval     = 30 * time.Second
	s2sPingTimeout      = 60 * time.Second
	s2sHandshakeTimeout = 15 * time.Second
)

// ServerLink represents a direct physical connection between two TS6 servers.
type ServerLink struct {
	server        *Server
	conn          IRCConn
	config        *LinkConfig
	inbound       bool
	remoteSID     string
	remoteName    string
	remoteDesc    string
	remoteNode    *ServerNode
	capabs        utils.HashSet[string]
	handshakeDone bool
	burstDone     bool
	sendChan      chan []byte
	closeChan     chan struct{}
	closed        atomic.Bool
	lastActive    atomic.Int64 // unix timestamp
	lastPingSent  time.Time
	lastPingNonce string
}

// NewServerLink creates a new ServerLink.
func NewServerLink(server *Server, conn IRCConn, config *LinkConfig, inbound bool) *ServerLink {
	link := &ServerLink{
		server:    server,
		conn:      conn,
		config:    config,
		inbound:   inbound,
		capabs:    make(utils.HashSet[string]),
		sendChan:  make(chan []byte, s2sSendQueueSize),
		closeChan: make(chan struct{}),
	}
	link.lastActive.Store(time.Now().Unix())
	return link
}

// RemoteSID returns the remote server's SID.
func (link *ServerLink) RemoteSID() string {
	return link.remoteSID
}

// RemoteName returns the remote server's name.
func (link *ServerLink) RemoteName() string {
	return link.remoteName
}

// IsClosed returns whether the link is closed.
func (link *ServerLink) IsClosed() bool {
	return link.closed.Load()
}

// HandshakeDone returns whether the link has completed the TS6 handshake.
func (link *ServerLink) HandshakeDone() bool {
	return link.handshakeDone
}

// BurstDone returns whether the link has finished the initial state burst.
func (link *ServerLink) BurstDone() bool {
	return link.burstDone
}

// SendLine enqueues an IRC line to be sent to the peer.
func (link *ServerLink) SendLine(line string) bool {
	if link.closed.Load() {
		return false
	}
	if !strings.HasSuffix(line, "\r\n") {
		line += "\r\n"
	}
	data := []byte(line)
	select {
	case link.sendChan <- data:
		return true
	case <-link.closeChan:
		return false
	default:
		// Send queue full, close link due to SendQ exceeded
		link.server.logger.Error("s2s", "SendQ exceeded on link", link.remoteName)
		go link.Close("SendQ exceeded")
		return false
	}
}

// SendMsg formats and sends an ircmsg.Message across the link.
func (link *ServerLink) SendMsg(msg ircmsg.Message) bool {
	line, err := msg.LineBytesStrict(false, MaxLineLen)
	if err != nil && err != ircmsg.ErrorBodyTooLong {
		link.server.logger.Error("s2s", "error formatting message", err.Error())
		return false
	}
	return link.SendLine(string(line))
}

// Send sends a command with prefix and parameters across the link.
func (link *ServerLink) Send(prefix string, command string, params ...string) bool {
	msg := ircmsg.MakeMessage(nil, prefix, command, params...)
	return link.SendMsg(msg)
}

// WriteLoop flushes queued messages to the socket.
func (link *ServerLink) WriteLoop() {
	defer func() {
		link.conn.Close()
	}()

	for {
		select {
		case data, ok := <-link.sendChan:
			if !ok {
				return
			}
			if err := link.conn.WriteLine(data); err != nil {
				link.server.logger.Debug("s2s", "write error on link", link.remoteName, err.Error())
				return
			}
		case <-link.closeChan:
			return
		}
	}
}

// ReadLoop reads and processes lines from the socket.
func (link *ServerLink) ReadLoop() {
	defer func() {
		link.Close("Connection closed")
	}()

	for {
		lineBytes, err := link.conn.ReadLine()
		if err != nil {
			link.server.logger.Debug("s2s", "read error on link", link.remoteName, err.Error())
			return
		}
		link.lastActive.Store(time.Now().Unix())

		line := strings.TrimRight(string(lineBytes), "\r\n")
		if len(line) == 0 {
			continue
		}

		if link.server.logger.IsLoggingRawIO() {
			link.server.logger.Debug("s2s-raw", link.remoteName, "<-", line)
		}

		msg, err := ircmsg.ParseLineStrict(line, false, MaxLineLen)
		if err != nil && err != ircmsg.ErrorBodyTooLong {
			link.server.logger.Debug("s2s", "error parsing line", line, err.Error())
			continue
		}

		if err := link.server.s2s.HandleLine(link, line, msg); err != nil {
			link.server.logger.Error("s2s", "fatal error handling line from link", link.remoteName, err.Error())
			return
		}
	}
}

// Close closes the server link and triggers netsplit cleanup.
func (link *ServerLink) Close(reason string) {
	if !link.closed.CompareAndSwap(false, true) {
		return
	}

	close(link.closeChan)
	link.conn.Close()

	link.server.logger.Info("s2s", "Link disconnected", link.remoteName, link.remoteSID, reason)
	link.server.s2s.HandleNetsplit(link, reason)
}

// StartPingTicker starts periodic keepalive pinging on the link.
func (link *ServerLink) StartPingTicker() {
	ticker := time.NewTicker(s2sPingInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if link.closed.Load() {
					return
				}
				last := time.Unix(link.lastActive.Load(), 0)
				if time.Since(last) > s2sPingTimeout {
					link.server.logger.Warning("s2s", "Ping timeout on link", link.remoteName)
					link.Close("Ping timeout")
					return
				}
				nonce := fmt.Sprintf("%d", time.Now().UnixNano())
				link.lastPingSent = time.Now()
				link.lastPingNonce = nonce
				link.Send(link.server.sid, "PING", link.server.sid, link.remoteSID)
			case <-link.closeChan:
				return
			}
		}
	}()
}
