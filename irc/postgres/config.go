// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package postgres

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
	Enabled         bool
	Host            string
	Port            int
	SocketPath      string `yaml:"socket-path"`
	User            string
	Password        string
	HistoryDatabase string `yaml:"history-database"`
	Timeout         time.Duration
	MaxConns        int           `yaml:"max-conns"`
	ConnMaxLifetime time.Duration `yaml:"conn-max-lifetime"`
	// PostgreSQL-specific configuration:
	ApplicationName string        `yaml:"application-name"` // shown in pg_stat_activity
	ConnectTimeout  time.Duration `yaml:"connect-timeout"`  // timeout for establishing connections
	// PostgreSQL SSL/TLS configuration:
	SSLMode     string `yaml:"ssl-mode"`      // disable, require, verify-ca, verify-full
	SSLCert     string `yaml:"ssl-cert"`      // client certificate path
	SSLKey      string `yaml:"ssl-key"`       // client key path
	SSLRootCert string `yaml:"ssl-root-cert"` // CA certificate path

	// XXX these are copied from elsewhere in the config:
	ExpireTime           time.Duration
	TrackAccountMessages bool
}
