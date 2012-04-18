package irc

import (
	"log"
	"net"
)

type Server struct {
	name string
	ch chan *ClientMessage
	nicks map[string]*Client
}

type ClientMessage struct {
	client *Client
	message Message
}

func NewServer(name string) *Server {
	server := new(Server)
	server.name = name
	server.ch = make(chan *ClientMessage)
	server.nicks = make(map[string]*Client)
	go server.Receive()
	return server
}

func (s *Server) Listen(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("Server.Listen: ", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print("Server.Listen: ", err)
			continue
		}
		go NewClient(conn).Communicate(s.ch)
	}
}

func (s *Server) Receive() {
	for m := range s.ch {
		m.message.Handle(s, m.client)
	}
}
