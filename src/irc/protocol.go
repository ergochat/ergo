package irc

import (
)

type Message struct {
	line string
	client *Client
}

func (m *Message) Encode() string {
	return m.line
}


// Adapt `chan string` to a `chan Message`.
func NewMessageChan(strch chan string) chan Message {
	msgch := make(chan Message)

	done := make(chan bool)
	go func() {
		<- done
		close(msgch)
	}()

	// str -> msg
	go func() {
		for str := range strch {
			msgch <- Message{str, nil}
		}
		done <- true
	}()

	// msg -> str
	go func() {
		for message := range msgch {
			strch <- message.Encode()
		}
		done <- true
	}()

	return msgch
}
