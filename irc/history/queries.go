// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package history

import (
	"strings"
	"time"
)

// Selector represents a parameter to a CHATHISTORY command
type Selector struct {
	Msgid string
	Time  time.Time
}

// Sequence is an abstract sequence of history entries that can be queried;
// it encapsulates restrictions such as registration time cutoffs, or
// only looking at a single "query buffer" (DMs with a particular correspondent)
type Sequence interface {
	Between(start, end Selector, limit int) (results []Item, err error)
	Around(start Selector, limit int) (results []Item, err error)

	// this are weird hacks that violate the encapsulation of Sequence to some extent;
	// Cutoff() returns the cutoff time for other code to use (it returns the zero time
	// if none is set), and Ephemeral() returns whether the backing store is in-memory
	// or a persistent database.
	Cutoff() time.Time
	Ephemeral() bool
}

// This is a bad, slow implementation of CHATHISTORY AROUND using the BETWEEN semantics
func GenericAround(seq Sequence, start Selector, limit int) (results []Item, err error) {
	var halfLimit int
	halfLimit = (limit + 1) / 2
	initialResults, err := seq.Between(Selector{}, start, halfLimit)
	if err != nil {
		return
	} else if len(initialResults) == 0 {
		// TODO: this fails if we're doing an AROUND on the first message in the buffer
		// would be nice to fix this but whatever
		return
	}
	newStart := Selector{Time: initialResults[0].Message.Time}
	results, err = seq.Between(newStart, Selector{}, limit)
	return
}

// MinMaxAsc converts CHATHISTORY arguments into time intervals, handling the most
// general case (BETWEEN going forwards or backwards) natively and the other ordering
// queries (AFTER, BEFORE, LATEST) as special cases.
func MinMaxAsc(after, before, cutoff time.Time) (min, max time.Time, ascending bool) {
	startIsZero, endIsZero := after.IsZero(), before.IsZero()
	if !startIsZero && endIsZero {
		// AFTER
		ascending = true
	} else if startIsZero && !endIsZero {
		// BEFORE
		ascending = false
	} else if !startIsZero && !endIsZero {
		if before.Before(after) {
			// BETWEEN going backwards
			before, after = after, before
			ascending = false
		} else {
			// BETWEEN going forwards
			ascending = true
		}
	} else if startIsZero && endIsZero {
		// LATEST
		ascending = false
	}
	if after.IsZero() || after.Before(cutoff) {
		// this may result in an impossible query, which is fine
		after = cutoff
	}
	return after, before, ascending
}

// maps regular msgids from JOIN, etc. to a msgid suitable for attaching
// to a HistServ message describing the JOIN. See #491 for some history.
func HistservMungeMsgid(msgid string) string {
	return "_" + msgid
}

// strips munging from a msgid. future schemes may not support a well-defined
// mapping of munged msgids to true msgids, but munged msgids should always contain
// a _, with metadata in front and data (possibly the true msgid) after.
func NormalizeMsgid(msgid string) string {
	return strings.TrimPrefix(msgid, "_")
}
