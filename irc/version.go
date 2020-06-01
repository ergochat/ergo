// Copyright (c) 2020 Shivaram Lingamneni
// Released under the MIT license

package irc

import "fmt"

const (
	// SemVer is the semantic version of Oragono.
	SemVer = "2.2.0-unreleased"
)

var (
	// Ver is the full version of Oragono, used in responses to clients.
	Ver = fmt.Sprintf("oragono-%s", SemVer)
	// Commit is the full git hash, if available
	Commit string
)

// initialize version strings (these are set in package main via linker flags)
func SetVersionString(version, commit string) {
	Commit = commit
	if version != "" {
		Ver = fmt.Sprintf("oragono-%s", version)
	} else if len(Commit) == 40 {
		Ver = fmt.Sprintf("oragono-%s-%s", SemVer, Commit[:16])
	}
}
