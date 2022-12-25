// Copyright (c) 2020 Shivaram Lingamneni
// Released under the MIT license

package irc

import "fmt"

const (
	// SemVer is the semantic version of Ergo.
	SemVer = "2.11.0"
)

var (
	// Ver is the full version of Ergo, used in responses to clients.
	Ver = fmt.Sprintf("ergo-%s", SemVer)
	// Commit is the full git hash, if available
	Commit string
)

// initialize version strings (these are set in package main via linker flags)
func SetVersionString(version, commit string) {
	Commit = commit
	if version != "" {
		Ver = fmt.Sprintf("ergo-%s", version)
	} else if len(Commit) == 40 {
		Ver = fmt.Sprintf("ergo-%s-%s", SemVer, Commit[:16])
	}
}
