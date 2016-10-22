// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import "fmt"

const (
	// SemVer is the semantic version of Oragono.
	SemVer = "0.3.0"
)

var (
	// Ver is the full version of Oragono, used in responses to clients.
	Ver = fmt.Sprintf("oragono-%s", SemVer)
)
