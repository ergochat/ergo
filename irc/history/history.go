// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package history

import (
	"github.com/oragono/oragono/irc/utils"
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
	Msgid       string
}

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
		item.Time = time.Now()
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

	if list.start == -1 {
		return
	}

	satisfies := func(itime time.Time) bool {
		return (after.IsZero() || itime.After(after)) && (before.IsZero() || itime.Before(before))
	}

	// TODO: if we can guarantee that the insertion order is also the monotonic clock order,
	// then this can do a single allocation and use binary search and 1-2 copy calls

	pos := list.prev(list.end)
	for {
		if satisfies(list.buffer[pos].Time) {
			results = append(results, list.buffer[pos])
		}
		if pos == list.start {
			break
		}
		pos = list.prev(pos)
	}

	// reverse the results
	for i, j := 0, len(results)-1; i < j; i, j = i+1, j-1 {
		results[i], results[j] = results[j], results[i]
	}
	return
}

// All returns all available history items as a slice
func (list *Buffer) All() (results []Item) {
	list.RLock()
	defer list.RUnlock()

	if list.start == -1 {
		return
	}
	results = make([]Item, list.length())
	if list.start < list.end {
		copy(results, list.buffer[list.start:list.end])
	} else {
		initialSegment := copy(results, list.buffer[list.start:])
		copy(results[initialSegment:], list.buffer[:list.end])
	}
	return
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
