package irc

import (
	"fmt"
)

// simple types

type ModeOp rune
type UserMode rune
type ChannelMode rune
type UserChannelMode rune
type Mask string

// interfaces

type Command interface {
	Client() *Client
	Source() Identifier
	Reply(Reply)
	HandleServer(*Server)
}

// structs

type UserMask struct {
	nickname Mask
	username Mask
	hostname Mask
}

func (mask *UserMask) String() string {
	return fmt.Sprintf("%s!%s@%s", mask.nickname, mask.username, mask.hostname)
}
