// Copyright (c) 2022 Valentin Lorentz
// released under the MIT license

// This file defines an abstraction over buntdb, allowing alternative
// backends (such as SQL databases) to be used instead of buntdb itself.

package kv

import (
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("not found")
)

type SetOptions struct {
	// Expires indicates that the Set() key-value will expire
	Expires bool
	// TTL is how much time the key-value will exist in the database
	// before being evicted. The Expires field must also be set to true.
	// TTL stands for Time-To-Live.
	TTL time.Duration
}

type Tx interface {
	AscendPrefix(prefix string, iterator func(key, value string) bool) error
	Delete(key string) (val string, err error)
	Get(key string, ignoreExpired ...bool) (val string, err error)
	Set(key string, value string, opts *SetOptions) (previousValue string, replaced bool, err error)
}

type Store interface {
	Close() error
	Update(fn func(tx Tx) error) error
	View(fn func(tx Tx) error) error
}
