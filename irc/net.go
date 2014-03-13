package irc

import (
	"net"
	"strings"
)

func IPString(addr net.Addr) Name {
	addrStr := addr.String()
	ipaddr, _, err := net.SplitHostPort(addrStr)
	if err != nil {
		return Name(addrStr)
	}
	return Name(ipaddr)
}

func AddrLookupHostname(addr net.Addr) Name {
	return LookupHostname(IPString(addr))
}

func LookupHostname(addr Name) Name {
	names, err := net.LookupAddr(addr.String())
	if err != nil {
		return Name(addr)
	}

	hostname := strings.TrimSuffix(names[0], ".")
	return Name(hostname)
}
