package irc

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

type ModeMessage struct {
	nickname string
	modes []string
}
