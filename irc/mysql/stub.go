//go:build !mysql

package mysql

// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

import (
	"errors"

	"github.com/ergochat/ergo/irc/history"
	"github.com/ergochat/ergo/irc/logger"
)

// Enabled is false when MySQL support is not compiled in
const Enabled = false

// MySQL is a stub implementation when the mysql build tag is not present
type MySQL struct {
	history.Database
}

// NewMySQLDatabase returns an error when MySQL support is not compiled in
func NewMySQLDatabase(logger *logger.Manager, config Config) (*MySQL, error) {
	return nil, errors.New("MySQL support not enabled in this build. Rebuild with `make build_full` to enable")
}

// SetConfig is a no-op for the stub implementation
func (m *MySQL) SetConfig(config Config) {
	// no-op
}
