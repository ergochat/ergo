// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package sqlite

import (
	"time"
)

const (
	// maximum length in bytes of any message target (nickname or channel name) in its
	// canonicalized (i.e., casefolded) state:
	MaxTargetLength = 64
)

type Config struct {
	// these are intended to be written directly into the config file:
	Enabled      bool
	DatabasePath string        `yaml:"database-path"`
	BusyTimeout  time.Duration `yaml:"busy-timeout"`
	MaxConns     int           `yaml:"max-conns"`

	// XXX these are copied from elsewhere in the config:
	ExpireTime           time.Duration
	TrackAccountMessages bool
}
