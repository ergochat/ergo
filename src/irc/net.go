package irc

import (
	"bufio"
	"net"
	"strings"
)

func readTrimmedLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// Adapt `net.Conn` to a `chan string`.
func StringReadChan(conn net.Conn) <-chan string {
	ch := make(chan string)
	reader := bufio.NewReader(conn)
	go func() {
		for {
			line, err := readTrimmedLine(reader)
			if err != nil {
				break
			}
			ch <- line
		}
		close(ch)
	}()
	return ch
}

func StringWriteChan(conn net.Conn) chan<- string {
	ch := make(chan string)
	writer := bufio.NewWriter(conn)
	go func() {
		for str := range ch {
			if _, err := writer.WriteString(str); err != nil {
				break
			}
			writer.Flush()
		}
		close(ch)
	}()

	return ch
}

func LookupHostname(addr net.Addr) string {
	addrStr := addr.String()
	ipaddr, _, err := net.SplitHostPort(addrStr)
	if err != nil {
		return addrStr
	}
	names, err := net.LookupAddr(ipaddr)
	if err != nil {
		return ipaddr
	}
	return names[0]
}
