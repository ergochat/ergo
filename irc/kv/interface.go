// Copyright (c) 2022 Valentin Lorentz
// released under the MIT license

// This file defines an abstraction over buntdb, allowing alternative
// backends (such as SQL databases) to be used instead of buntdb itself.

package kv

import (
	"github.com/tidwall/buntdb"
)

type Tx interface {
	AscendKeys(pattern string, iterator func(key, value string) bool) error
	AscendGreaterOrEqual(index, pivot string, iterator func(key, value string) bool) error
	Delete(key string) (val string, err error)
	Get(key string, ignoreExpired ...bool) (val string, err error)
	Set(key string, value string, opts *buntdb.SetOptions) (previousValue string, replaced bool, err error)
}

type Store interface {
	Close() error
	Update(fn func(tx Tx) error) error
	View(fn func(tx Tx) error) error
}
