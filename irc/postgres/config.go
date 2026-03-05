// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package postgres

import (
	"fmt"
	"net/url"
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
	URI         string `yaml:"uri"`           // libpq postgresql:// URI overriding the above

	// XXX these are copied from elsewhere in the config:
	ExpireTime           time.Duration
	TrackAccountMessages bool
}

func (config *Config) buildURI() (string, error) {
	u := &url.URL{
		Scheme: "postgresql",
		Path:   "/" + config.HistoryDatabase,
	}

	q := url.Values{}

	if config.SocketPath != "" {
		// For Unix sockets, pgx uses host as a query parameter
		q.Set("host", config.SocketPath)
		if config.User != "" || config.Password != "" {
			u.User = url.UserPassword(config.User, config.Password)
		}
	} else {
		// TCP connection
		port := config.Port
		if port == 0 {
			port = 5432
		}
		host := config.Host
		if host == "" {
			host = "localhost"
		}
		u.Host = fmt.Sprintf("%s:%d", host, port)
		if config.User != "" || config.Password != "" {
			u.User = url.UserPassword(config.User, config.Password)
		}

		sslMode := config.SSLMode
		if sslMode == "" {
			sslMode = "disable"
		}
		q.Set("sslmode", sslMode)

		if config.SSLCert != "" {
			q.Set("sslcert", config.SSLCert)
		}
		if config.SSLKey != "" {
			q.Set("sslkey", config.SSLKey)
		}
		if config.SSLRootCert != "" {
			q.Set("sslrootcert", config.SSLRootCert)
		}
	}

	if config.ApplicationName != "" {
		q.Set("application_name", config.ApplicationName)
	}
	if config.ConnectTimeout != 0 {
		q.Set("connect_timeout", fmt.Sprintf("%d", int(config.ConnectTimeout.Seconds())))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
