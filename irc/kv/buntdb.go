// Copyright (c) 2022 Valentin Lorentz
// released under the MIT license

// This file implements the Store abstraction using buntdb.
// As the abstraction itself is based on buntdb's API, this is mostly
// a pass-through.

package kv

import (
	"github.com/tidwall/buntdb"
)

type BuntdbStore struct {
	db *buntdb.DB
}

func BuntdbOpen(path string) (Store, error) {
	store, err := buntdb.Open(path)
	return BuntdbStore{store}, err
}

func (db BuntdbStore) Close() error {
	return db.db.Close()
}

func (kv BuntdbStore) Update(fn func(tx Tx) error) error {
	return kv.db.Update(func(tx *buntdb.Tx) error {
		return fn(tx)
	})
}

func (kv BuntdbStore) View(fn func(tx Tx) error) error {
	return kv.db.View(func(tx *buntdb.Tx) error {
		return fn(tx)
	})
}
