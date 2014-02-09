package irc

import (
	"bufio"
	"log"
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
		defer conn.Close()
		defer close(ch)
		for {
			line, err := readTrimmedLine(reader)
			if err != nil {
				log.Print("net: ", err)
				break
			}
			if DEBUG_NET {
				log.Printf("%s → %s : %s", conn.RemoteAddr(), conn.LocalAddr(), line)
			}
			ch <- line
		}
	}()
	return ch
}

func StringWriteChan(conn net.Conn) chan<- string {
	ch := make(chan string)
	writer := bufio.NewWriter(conn)
	go func() {
		defer conn.Close()
		defer close(ch)
		for str := range ch {
			if DEBUG_NET {
				log.Printf("%s ← %s : %s", conn.RemoteAddr(), conn.LocalAddr(), str)
			}
			if _, err := writer.WriteString(str + "\r\n"); err != nil {
				log.Print("net: ", err)
				break
			}
			writer.Flush()
		}
	}()
	return ch
}

func LookupHostname(addr net.Addr) string {
	addrStr := addr.String()
	ipaddr, _, err := net.SplitHostPort(addrStr)
	if err != nil {
		return addrStr
	}
	names, err := net.LookupHost(ipaddr)
	if err != nil {
		return ipaddr
	}
	return names[0]
}
