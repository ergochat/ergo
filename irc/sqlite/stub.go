//go:build !sqlite || !(linux || darwin || freebsd || windows)

// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

// Package sqlite provides a stub implementation when SQLite support is not enabled.
// To enable SQLite support, build with: make build_full
// This stub prevents the binary from including the large modernc.org/sqlite driver dependencies.
package sqlite

import (
	"errors"

	"github.com/ergochat/ergo/irc/history"
	"github.com/ergochat/ergo/irc/logger"
)

// Enabled is false when SQLite support is not compiled in
const Enabled = false

// SQLite is a stub implementation when the sqlite build tag is not present
type SQLite struct {
	history.Database
}

// NewSQLiteDatabase returns an error when SQLite support is not compiled in
func NewSQLiteDatabase(logger *logger.Manager, config Config) (*SQLite, error) {
	return nil, errors.New("SQLite support not enabled in this build. Rebuild with `make build_full` to enable")
}

// SetConfig is a no-op for the stub implementation
func (s *SQLite) SetConfig(config Config) {
	// no-op
}
