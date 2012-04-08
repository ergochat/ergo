package irc

import (
	"bufio"
	"log"
	"strings"
	"net"
)

// Adapt `net.Conn` to a `chan string`.
func StringReadChan(conn net.Conn) chan string {
	ch := make(chan string)
	reader := bufio.NewReader(conn)
	go func() {
		for {
			line, err := reader.ReadString('\n')
			if (line != "") {
				ch <- strings.TrimSpace(line)
			}
			if err != nil {
				log.Print("StringReadChan[read]: ", err)
				break
			}
		}
		close(ch)
	}()
	return ch
}

func StringWriteChan(conn net.Conn) chan string {
	ch := make(chan string)
	writer := bufio.NewWriter(conn)
	go func() {
		for str := range ch {
			if _, err := writer.WriteString(str + "\r\n"); err != nil {
				log.Print("StringWriteChan[write]: ", err)
				break
			}
			writer.Flush()
		}
		close(ch)
	}()

	return ch
}
