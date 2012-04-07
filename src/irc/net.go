package irc

import (
	"bufio"
	"log"
	"net"
)

// Adapt `net.Conn` to a `chan string`.
func NewStringChan(conn net.Conn) chan string {
	ch := make(chan string)
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	done := make(chan bool)
	go func() {
		<- done
		close(ch)
	}()

	// conn -> ch
	go func() {
		for {
			line, err := rw.ReadString('\n')
			if err != nil {
				log.Print("StringChan[read]: %v", err)
				break
			}
			ch <- line
		}
		done <- true
	}()

	// ch -> conn
	go func() {
		for str := range ch {
			if _, err := rw.WriteString(str + "\r\n"); err != nil {
				log.Print("StringChan[write]: %v", err)
				break
			}
			rw.Flush()
		}
		done <- true
	}()

	return ch
}
