// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package history

import (
	"github.com/unendingPattern/oragono/irc/utils"
	"sync"
	"sync/atomic"
	"time"
)

type ItemType uint

const (
	uninitializedItem ItemType = iota
	Privmsg
	Notice
	Join
	Part
	Kick
	Quit
	Mode
)

// Item represents an event (e.g., a PRIVMSG or a JOIN) and its associated data
type Item struct {
	Type ItemType
	Time time.Time

	Nick string
	// this is the uncasefolded account name, if there's no account it should be set to "*"
	AccountName string
	Message     utils.SplitMessage
	// for non-privmsg items, we may stuff some other data in here
	Msgid string
}

type Predicate func(item Item) (matches bool)

// Buffer is a ring buffer holding message/event history for a channel or user
type Buffer struct {
	sync.RWMutex

	// ring buffer, see irc/whowas.go for conventions
	buffer []Item
	start  int
	end    int

	lastDiscarded time.Time

	enabled uint32
}

func NewHistoryBuffer(size int) (result *Buffer) {
	result = new(Buffer)
	result.Initialize(size)
	return
}

func (hist *Buffer) Initialize(size int) {
	hist.buffer = make([]Item, size)
	hist.start = -1
	hist.end = -1

	hist.setEnabled(size)
}

func (hist *Buffer) setEnabled(size int) {
	var enabled uint32
	if size != 0 {
		enabled = 1
	}
	atomic.StoreUint32(&hist.enabled, enabled)
}

// Enabled returns whether the buffer is currently storing messages
// (a disabled buffer blackholes everything it sees)
func (list *Buffer) Enabled() bool {
	return atomic.LoadUint32(&list.enabled) != 0
}

// Add adds a history item to the buffer
func (list *Buffer) Add(item Item) {
	// fast path without a lock acquisition for when we are not storing history
	if !list.Enabled() {
		return
	}

	if item.Time.IsZero() {
		item.Time = time.Now().UTC()
	}

	list.Lock()
	defer list.Unlock()

	var pos int
	if list.start == -1 { // empty
		pos = 0
		list.start = 0
		list.end = 1 % len(list.buffer)
	} else if list.start != list.end { // partially full
		pos = list.end
		list.end = (list.end + 1) % len(list.buffer)
	} else if list.start == list.end { // full
		pos = list.end
		list.end = (list.end + 1) % len(list.buffer)
		list.start = list.end // advance start as well, overwriting first entry
		// record the timestamp of the overwritten item
		if list.lastDiscarded.Before(list.buffer[pos].Time) {
			list.lastDiscarded = list.buffer[pos].Time
		}
	}

	list.buffer[pos] = item
}

func reverse(results []Item) {
	for i, j := 0, len(results)-1; i < j; i, j = i+1, j-1 {
		results[i], results[j] = results[j], results[i]
	}
}

// Between returns all history items with a time `after` <= time <= `before`,
// with an indication of whether the results are complete or are missing items
// because some of that period was discarded. A zero value of `before` is considered
// higher than all other times.
func (list *Buffer) Between(after, before time.Time) (results []Item, complete bool) {
	if !list.Enabled() {
		return
	}

	list.RLock()
	defer list.RUnlock()

	complete = after.Equal(list.lastDiscarded) || after.After(list.lastDiscarded)

	satisfies := func(item Item) bool {
		return (after.IsZero() || item.Time.After(after)) && (before.IsZero() || item.Time.Before(before))
	}

	return list.matchInternal(satisfies, 0), complete
}

// Match returns all history items such that `predicate` returns true for them.
// Items are considered in reverse insertion order, up to a total of `limit` matches.
// `predicate` MAY be a closure that maintains its own state across invocations;
// it MUST NOT acquire any locks or otherwise do anything weird.
func (list *Buffer) Match(predicate Predicate, limit int) (results []Item) {
	if !list.Enabled() {
		return
	}

	list.RLock()
	defer list.RUnlock()

	return list.matchInternal(predicate, limit)
}

// you must be holding the read lock to call this
func (list *Buffer) matchInternal(predicate Predicate, limit int) (results []Item) {
	if list.start == -1 {
		return
	}

	pos := list.prev(list.end)
	for {
		if predicate(list.buffer[pos]) {
			results = append(results, list.buffer[pos])
		}
		if pos == list.start || (limit != 0 && len(results) == limit) {
			break
		}
		pos = list.prev(pos)
	}

	// TODO sort by time instead?
	reverse(results)
	return
}

// Latest returns the items most recently added, up to `limit`. If `limit` is 0,
// it returns all items.
func (list *Buffer) Latest(limit int) (results []Item) {
	matchAll := func(item Item) bool { return true }
	return list.Match(matchAll, limit)
}

// LastDiscarded returns the latest time of any entry that was evicted
// from the ring buffer.
func (list *Buffer) LastDiscarded() time.Time {
	list.RLock()
	defer list.RUnlock()

	return list.lastDiscarded
}

func (list *Buffer) prev(index int) int {
	switch index {
	case 0:
		return len(list.buffer) - 1
	default:
		return index - 1
	}
}

// Resize shrinks or expands the buffer
func (list *Buffer) Resize(size int) {
	newbuffer := make([]Item, size)
	list.Lock()
	defer list.Unlock()

	list.setEnabled(size)

	if list.start == -1 {
		// indices are already correct and nothing needs to be copied
	} else if size == 0 {
		// this is now the empty list
		list.start = -1
		list.end = -1
	} else {
		currentLength := list.length()
		start := list.start
		end := list.end
		// if we're truncating, keep the latest entries, not the earliest
		if size < currentLength {
			start = list.end - size
			if start < 0 {
				start += len(list.buffer)
			}
			// update lastDiscarded for discarded entries
			for i := list.start; i != start; i = (i + 1) % len(list.buffer) {
				if list.lastDiscarded.Before(list.buffer[i].Time) {
					list.lastDiscarded = list.buffer[i].Time
				}
			}
		}
		if start < end {
			copied := copy(newbuffer, list.buffer[start:end])
			list.start = 0
			list.end = copied % size
		} else {
			lenInitial := len(list.buffer) - start
			copied := copy(newbuffer, list.buffer[start:])
			copied += copy(newbuffer[lenInitial:], list.buffer[:end])
			list.start = 0
			list.end = copied % size
		}
	}

	list.buffer = newbuffer
}

func (hist *Buffer) length() int {
	if hist.start == -1 {
		return 0
	} else if hist.start < hist.end {
		return hist.end - hist.start
	} else {
		return len(hist.buffer) - (hist.start - hist.end)
	}
}
