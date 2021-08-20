//go:build !linux
// +build !linux

package utils

import (
	"fmt"
	"net"
)

// Output a description of a connection that can identify it to other systems
// administration tools.
func DescribeConn(conn net.Conn) (description string) {
	return fmt.Sprintf("%s <-> %s", conn.LocalAddr().String(), conn.RemoteAddr().String())
}
