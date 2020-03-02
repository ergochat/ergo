// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import "fmt"

const (
	// SemVer is the semantic version of Oragono.
	SemVer = "2.0.0-rc1"
)

var (
	// Commit is the current git commit.
	Commit = ""

	// Ver is the full version of Oragono, used in responses to clients.
	Ver = fmt.Sprintf("oragono-%s", SemVer)

	// maxLastArgLength is used to simply cap off the final argument when creating general messages where we need to select a limit.
	// for instance, in MONITOR lists, RPL_ISUPPORT lists, etc.
	maxLastArgLength = 400
	// maxTargets is the maximum number of targets for PRIVMSG and NOTICE.
	maxTargets = 4
)
