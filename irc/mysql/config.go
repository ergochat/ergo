// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package mysql

import (
	"time"
)

type Config struct {
	// these are intended to be written directly into the config file:
	Enabled         bool
	Host            string
	Port            int
	User            string
	Password        string
	HistoryDatabase string `yaml:"history-database"`
	Timeout         time.Duration

	// XXX these are copied from elsewhere in the config:
	ExpireTime time.Duration
}
