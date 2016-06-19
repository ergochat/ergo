// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"net"
	"strings"

	"github.com/DanielOaks/girc-go/ircmsg"
)

// ClientSocket listens to a socket using the IRC protocol, processes events,
// and also sends IRC lines out of that socket.
type ClientSocket struct {
	receiveLines  chan string
	ReceiveEvents chan Message
	SendLines     chan string
	socket        Socket
	client        Client
}

// NewClientSocket returns a new ClientSocket.
func NewClientSocket(conn net.Conn, client Client) ClientSocket {
	return ClientSocket{
		receiveLines:  make(chan string),
		ReceiveEvents: make(chan Message),
		SendLines:     make(chan string),
		socket:        NewSocket(conn),
		client:        client,
	}
}

// Start creates and starts running the necessary event loops.
func (cs *ClientSocket) Start() {
	go cs.RunEvents()
	go cs.RunSocketSender()
	go cs.RunSocketListener()
}

// RunEvents handles received IRC lines and processes incoming commands.
func (cs *ClientSocket) RunEvents() {
	var exiting bool
	var line string
	for {
		select {
		case line = <-cs.receiveLines:
			if line != "" {
				fmt.Println("<- ", strings.TrimRight(line, "\r\n"))
				exiting = cs.processIncomingLine(line)
				if exiting {
					cs.socket.Close()
					break
				}
			}
		}
	}
	// empty the receiveLines queue
	select {
	case <-cs.receiveLines:
		// empty
	default:
		// empty
	}
}

// RunSocketSender sends lines to the IRC socket.
func (cs *ClientSocket) RunSocketSender() {
	var err error
	var line string
	for {
		line = <-cs.SendLines
		err = cs.socket.Write(line)
		fmt.Println(" ->", strings.TrimRight(line, "\r\n"))
		if err != nil {
			break
		}
	}
}

// RunSocketListener receives lines from the IRC socket.
func (cs *ClientSocket) RunSocketListener() {
	var errConn error
	var line string

	for {
		line, errConn = cs.socket.Read()
		cs.receiveLines <- line
		if errConn != nil {
			break
		}
	}
	if !cs.socket.Closed {
		cs.Send(nil, "", "ERROR", "Closing connection")
		cs.socket.Close()
	}
}

// Send sends an IRC line to the listener.
func (cs *ClientSocket) Send(tags *map[string]ircmsg.TagValue, prefix string, command string, params ...string) error {
	ircmsg := ircmsg.MakeMessage(tags, prefix, command, params...)
	line, err := ircmsg.Line()
	if err != nil {
		return err
	}
	cs.SendLines <- line
	return nil
}

// processIncomingLine splits and handles the given command line.
// Returns true if client is exiting (sent a QUIT command, etc).
func (cs *ClientSocket) processIncomingLine(line string) bool {
	msg, err := ircmsg.ParseLine(line)
	if err != nil {
		cs.Send(nil, "", "ERROR", "Your client sent a malformed line")
		return true
	}

	command, canBeParsed := Commands[msg.Command]

	if canBeParsed {
		return command.Run(cs.client.server, &cs.client, msg)
	}
	//TODO(dan): This is an error+disconnect purely for reasons of testing.
	// Later it may be downgraded to not-that-bad.
	cs.Send(nil, "", "ERROR", fmt.Sprintf("Your client sent a command that could not be parsed [%s]", msg.Command))
	return true
}
