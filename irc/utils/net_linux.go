//go:build linux
// +build linux

package utils

import (
	"fmt"
	"net"
	"syscall"
)

// Output a description of a connection that can identify it to other systems
// administration tools.
func DescribeConn(c net.Conn) (description string) {
	description = "<error>"
	switch conn := c.(type) {
	case *net.UnixConn:
		f, err := conn.File()
		if err != nil {
			return
		}
		defer f.Close()
		ucred, err := syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			return
		}
		return fmt.Sprintf("%s <-> %s [pid=%d, uid=%d]", conn.LocalAddr().String(), conn.RemoteAddr().String(), ucred.Pid, ucred.Uid)
	default:
		// *net.TCPConn or *tls.Conn
		return fmt.Sprintf("%s <-> %s", conn.LocalAddr().String(), conn.RemoteAddr().String())
	}
}
