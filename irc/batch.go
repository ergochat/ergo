// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"strconv"
	"time"

	"github.com/goshuirc/irc-go/ircmsg"
	"github.com/unendingPattern/oragono/irc/caps"
)

const (
	// maxBatchID is the maximum ID the batch counter can get to before it rotates.
	//
	// Batch IDs are made up of the current unix timestamp plus a rolling int ID that's
	// incremented for every new batch. It's an alright solution and will work unless we get
	// more than maxId batches per nanosecond. Later on when we have S2S linking, the batch
	// ID will also contain the server ID to ensure they stay unique.
	maxBatchID uint64 = 60000
)

// BatchManager helps generate new batches and new batch IDs.
type BatchManager struct {
	idCounter uint64
}

// NewBatchManager returns a new Manager.
func NewBatchManager() *BatchManager {
	return &BatchManager{}
}

// NewID returns a new batch ID that should be unique.
func (bm *BatchManager) NewID() string {
	bm.idCounter++
	if maxBatchID < bm.idCounter {
		bm.idCounter = 0
	}

	return strconv.FormatInt(time.Now().UnixNano(), 36) + strconv.FormatUint(bm.idCounter, 36)
}

// Batch represents an IRCv3 batch.
type Batch struct {
	ID     string
	Type   string
	Params []string
}

// New returns a new batch.
func (bm *BatchManager) New(batchType string, params ...string) *Batch {
	newBatch := Batch{
		ID:     bm.NewID(),
		Type:   batchType,
		Params: params,
	}

	return &newBatch
}

// Start sends the batch start message to this client
func (b *Batch) Start(client *Client, tags *map[string]ircmsg.TagValue) {
	if client.capabilities.Has(caps.Batch) {
		params := []string{"+" + b.ID, b.Type}
		for _, param := range b.Params {
			params = append(params, param)
		}
		client.Send(tags, client.server.name, "BATCH", params...)
	}
}

// End sends the batch end message to this client
func (b *Batch) End(client *Client) {
	if client.capabilities.Has(caps.Batch) {
		client.Send(nil, client.server.name, "BATCH", "-"+b.ID)
	}
}
