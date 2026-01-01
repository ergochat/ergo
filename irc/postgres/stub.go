//go:build !postgres

// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

// Package postgres provides a stub implementation when PostgreSQL support is not enabled.
// To enable PostgreSQL support, build with: make build_full
// This stub prevents the binary from including the large pgx PostgreSQL driver dependencies.
package postgres

import (
	"errors"

	"github.com/ergochat/ergo/irc/history"
	"github.com/ergochat/ergo/irc/logger"
)

// Enabled is false when PostgreSQL support is not compiled in
const Enabled = false

// PostgreSQL is a stub implementation when the postgres build tag is not present
type PostgreSQL struct {
	history.Database
}

// NewPostgreSQLDatabase returns an error when PostgreSQL support is not compiled in
func NewPostgreSQLDatabase(logger *logger.Manager, config Config) (*PostgreSQL, error) {
	return nil, errors.New("PostgreSQL support not enabled in this build. Rebuild with `make build_full` to enable")
}

// SetConfig is a no-op for the stub implementation
func (pg *PostgreSQL) SetConfig(config Config) {
	// no-op
}
