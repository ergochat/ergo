package irc

import (
	"bufio"
	"log"
	"strings"
	"net"
)

func readTrimmedLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	return strings.TrimSpace(line), err
}

// Adapt `net.Conn` to a `chan string`.
func StringReadChan(conn net.Conn) <-chan string {
	ch := make(chan string)
	reader := bufio.NewReader(conn)
	go func() {
		for {
			line, err := readTrimmedLine(reader)
			if (line != "") {
				ch <- line
				log.Printf("%s -> %s", conn.RemoteAddr(), line)
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
	go func() {
		for str := range ch {
			if _, err := writer.WriteString(str + "\r\n"); err != nil {
				break
			}
			writer.Flush()
			log.Printf("%s <- %s", conn.RemoteAddr(), str)
		}
		close(ch)
	}()

	return ch
}
