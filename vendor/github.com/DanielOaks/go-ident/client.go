// Package ident implements an RFC 1413 client
package ident

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// Response is a successful answer to our query to the identd server.
type Response struct {
	OS         string
	Charset    string
	Identifier string
}

// ResponseError indicates that the identd server returned an error rather than an
// identifying string.
type ResponseError struct {
	Type string
}

func (e ResponseError) Error() string {
	return fmt.Sprintf("Ident error: %s", e.Type)
}

// ProtocolError indicates that an error occurred with the protocol itself, that the response
// could not be successfully parsed or was malformed.
type ProtocolError struct {
	Line string
}

func (e ProtocolError) Error() string {
	return fmt.Sprintf("Unexpected response from server: %s", e.Line)
}

// Query makes an Ident query, if timeout is >0 the query is timed out after that many seconds.
func Query(ip string, portOnServer, portOnClient int, timeout float64) (Response, error) {
	var (
		conn   net.Conn
		err    error
		fields []string
		r      *bufio.Reader
		resp   string
	)

	conn, err = net.Dial("tcp", net.JoinHostPort(ip, "113"))
	if err != nil {
		goto Error
	}

	// stop the ident read after <timeout> seconds
	if timeout > 0 {
		conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
	}

	_, err = conn.Write([]byte(fmt.Sprintf("%d, %d", portOnServer, portOnClient) + "\r\n"))
	if err != nil {
		goto Error
	}

	r = bufio.NewReader(conn)
	resp, err = r.ReadString('\n')
	if err != nil {
		goto Error
	}

	fields = strings.SplitN(strings.TrimSpace(resp), " : ", 4)
	if len(fields) < 3 {
		goto ProtocolError
	}

	switch fields[1] {
	case "USERID":
		if len(fields) != 4 {
			goto ProtocolError
		}

		var os, charset string
		osAndCharset := strings.SplitN(fields[2], ",", 2)
		if len(osAndCharset) == 2 {
			os = osAndCharset[0]
			charset = osAndCharset[1]
		} else {
			os = osAndCharset[0]
			charset = "US-ASCII"
		}

		return Response{
			OS:         os,
			Charset:    charset,
			Identifier: fields[3],
		}, nil
	case "ERROR":
		if len(fields) != 3 {
			goto ProtocolError
		}

		return Response{}, ResponseError{fields[3]}
	}
ProtocolError:
	return Response{}, ProtocolError{resp}
Error:
	return Response{}, err
}
