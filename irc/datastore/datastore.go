// Copyright (c) 2022 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package datastore

import (
	"time"

	"github.com/ergochat/ergo/irc/utils"
)

type Table uint16

// XXX these are persisted and must remain stable;
// do not reorder, when deleting use _ to ensure that the deleted value is skipped
const (
	TableMetadata Table = iota
	TableChannels
	TableChannelPurges
)

type KV struct {
	UUID  utils.UUID
	Value []byte
}

// A Datastore provides the following abstraction:
// 1. Tables, each keyed on a UUID (the implementation is free to merge
// the table name and the UUID into a single key as long as the rest of
// the contract can be satisfied). Table names are [a-z0-9_]+
// 2. The ability to efficiently enumerate all uuid-value pairs in a table
// 3. Gets, sets, and deletes for individual (table, uuid) keys
type Datastore interface {
	Backoff() time.Duration

	GetAll(table Table) ([]KV, error)

	// This is rarely used because it would typically lead to TOCTOU races
	Get(table Table, key utils.UUID) (value []byte, err error)

	Set(table Table, key utils.UUID, value []byte, expiration time.Time) error

	// Note that deleting a nonexistent key is not considered an error
	Delete(table Table, key utils.UUID) error
}
