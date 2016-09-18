// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import "fmt"

const (
	SEM_VER       = "0.2.0-unreleased"
	CRLF          = "\r\n"
	MAX_REPLY_LEN = 512 - len(CRLF)
)

var (
	VER = fmt.Sprintf("oragono-%s", SEM_VER)
)
