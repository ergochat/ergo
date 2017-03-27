// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package web

// Server is the webserver
type Server struct {
}

// NewServer returns a new Oragono server.
func NewServer(config *Config) *Server {
	server := &Server{}

	return server
}

func (*Server) Run() {

}
