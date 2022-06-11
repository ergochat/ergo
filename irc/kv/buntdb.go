// Copyright (c) 2022 Valentin Lorentz
// released under the MIT license

// This file implements the Store abstraction using buntdb.
// As the abstraction itself is based on buntdb's API, this is mostly
// a pass-through.

package kv

import (
	"github.com/tidwall/buntdb"
)

/**********************
 * Transactions
 */
type BuntdbTx struct {
	tx *buntdb.Tx
}

func (tx BuntdbTx) AscendKeys(pattern string, iterator func(key, value string) bool) error {
	return tx.tx.AscendKeys(pattern, iterator)
}

func (tx BuntdbTx) AscendGreaterOrEqual(index, pivot string, iterator func(key, value string) bool) error {
	return tx.tx.AscendGreaterOrEqual(index, pivot, iterator)
}

func (tx BuntdbTx) Delete(key string) (val string, err error) {
	return tx.tx.Delete(key)
}

func (tx BuntdbTx) Get(key string, ignoreExpired ...bool) (val string, err error) {
	return tx.tx.Get(key, ignoreExpired...)
}

func (tx BuntdbTx) Set(key string, value string, opts *SetOptions) (previousValue string, replaced bool, err error) {
	var buntdbOpts *buntdb.SetOptions
	if opts == nil {
		buntdbOpts = nil
	} else {
		buntdbOpts = &buntdb.SetOptions{Expires: opts.Expires, TTL: opts.TTL}
	}
	return tx.tx.Set(key, value, buntdbOpts)
}

/**********************
 * Database
 */

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
		return fn(BuntdbTx{tx})
	})
}

func (kv BuntdbStore) View(fn func(tx Tx) error) error {
	return kv.db.View(func(tx *buntdb.Tx) error {
		return fn(BuntdbTx{tx})
	})
}
