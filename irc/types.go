package irc

import (
	"fmt"
)

//
// simple types
//

// a string with wildcards
type Mask string

// add, remove, list modes
type ModeOp rune

// user mode flags
type UserMode rune

// channel mode flags
type ChannelMode rune

// user-channel mode flags
type UserChannelMode rune

//
// interfaces
//

// commands the server understands
// TODO rename ServerCommand
type Command interface {
	Client() *Client
	Source() Identifier
	Reply(Reply)
	HandleServer(*Server)
}

//
// structs
//

type UserMask struct {
	nickname Mask
	username Mask
	hostname Mask
}

func (mask *UserMask) String() string {
	return fmt.Sprintf("%s!%s@%s", mask.nickname, mask.username, mask.hostname)
}
