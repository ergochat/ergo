package irc

import (
	"bufio"
	"log"
	"net"
	"strings"
)

func readTrimmedLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	return strings.TrimSpace(line), err
}

// Adapt `net.Conn` to a `chan string`.
func StringReadChan(conn net.Conn) <-chan string {
	ch := make(chan string)
	reader := bufio.NewReader(conn)
	addr := conn.RemoteAddr()
	go func() {
		for {
			line, err := readTrimmedLine(reader)
			if line != "" {
				ch <- line
				log.Printf("%s -> %s", addr, line)
			}
			if err != nil {
				break
			}
		}
		close(ch)
	}()
	return ch
}

func StringWriteChan(conn net.Conn) chan<- string {
	ch := make(chan string)
	writer := bufio.NewWriter(conn)
	addr := conn.RemoteAddr()
	go func() {
		for str := range ch {
			if _, err := writer.WriteString(str + "\r\n"); err != nil {
				break
			}
			writer.Flush()
			log.Printf("%s <- %s", addr, str)
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
