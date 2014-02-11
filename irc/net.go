package irc

import (
	"net"
	"strings"
)

func AddrLookupHostname(addr net.Addr) string {
	addrStr := addr.String()
	ipaddr, _, err := net.SplitHostPort(addrStr)
	if err != nil {
		return addrStr
	}
	return LookupHostname(ipaddr)
}

func LookupHostname(addr string) string {
	names, err := net.LookupAddr(addr)
	if err != nil {
		return addr
	}
	return strings.TrimSuffix(names[0], ".")
}
