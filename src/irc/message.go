package irc

type Message interface {
	Handle(s *Server, c *Client)
}

type NickMessage struct {
	nickname string
}

type UserMessage struct {
	user string
	mode uint8
	unused string
	realname string
}


type QuitMessage struct {
	message string
}

type UnknownMessage struct {
	command string
}

type PingMessage struct {}
