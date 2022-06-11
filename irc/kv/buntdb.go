// Copyright (c) 2022 Valentin Lorentz
// released under the MIT license

// This file implements the Store abstraction using buntdb.
// As the abstraction itself is based on buntdb's API, this is mostly
// a pass-through.

package kv

import (
	"github.com/tidwall/buntdb"
)

func convertError(err error) error {
	if err == buntdb.ErrNotFound {
		return ErrNotFound
	} else {
		return err
	}
}

/**********************
 * Transactions
 */
type BuntdbTx struct {
	tx *buntdb.Tx
}

func (tx BuntdbTx) AscendGreaterOrEqual(index, pivot string, iterator func(key, value string) bool) error {
	return convertError(tx.tx.AscendGreaterOrEqual(index, pivot, iterator))
}

func (tx BuntdbTx) Delete(key string) (val string, err error) {
	val, err = tx.tx.Delete(key)
	return val, convertError(err)
}

func (tx BuntdbTx) Get(key string, ignoreExpired ...bool) (val string, err error) {
	val, err = tx.tx.Get(key, ignoreExpired...)
	return val, convertError(err)
}

func (tx BuntdbTx) Set(key string, value string, opts *SetOptions) (previousValue string, replaced bool, err error) {
	var buntdbOpts *buntdb.SetOptions
	if opts == nil {
		buntdbOpts = nil
	} else {
		buntdbOpts = &buntdb.SetOptions{Expires: opts.Expires, TTL: opts.TTL}
	}
	previousValue, replaced, err = tx.tx.Set(key, value, buntdbOpts)
	return previousValue, replaced, convertError(err)
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
