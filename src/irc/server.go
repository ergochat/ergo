package irc

import (
	"log"
	"net"
)

type Server struct {
	ch chan Message
}

func NewServer() *Server {
	server := Server{make(chan Message)}
	go server.Receive()
	return &server
}

func (s *Server) Listen(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("Server.Listen: %v", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print("Server.Listen: %v", err)
			continue
		}
		client := NewClient(conn)
		go client.Communicate(s.ch)
	}
}

func (s *Server) Receive() {
	for message := range s.ch {
		log.Print("Server.Receive: %v", message.line)
		message.client.ch <- Message{"pong: " + message.line, nil}
	}
}

func (s *Server) Close() {
	close(s.ch)
}
