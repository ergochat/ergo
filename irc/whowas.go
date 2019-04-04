// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"sync"
)

// WhoWasList holds our list of prior clients (for use with the WHOWAS command).
type WhoWasList struct {
	buffer []WhoWas
	// three possible states:
	// empty: start == end == -1
	// partially full: start != end
	// full: start == end > 0
	// if entries exist, they go from `start` to `(end - 1) % length`
	start int
	end   int

	accessMutex sync.RWMutex // tier 1
}

// NewWhoWasList returns a new WhoWasList
func (list *WhoWasList) Initialize(size int) {
	list.buffer = make([]WhoWas, size)
	list.start = -1
	list.end = -1
}

// Append adds an entry to the WhoWasList.
func (list *WhoWasList) Append(whowas WhoWas) {
	list.accessMutex.Lock()
	defer list.accessMutex.Unlock()

	if len(list.buffer) == 0 {
		return
	}

	var pos int
	if list.start == -1 { // empty
		pos = 0
		list.start = 0
		list.end = 1
	} else if list.start != list.end { // partially full
		pos = list.end
		list.end = (list.end + 1) % len(list.buffer)
	} else if list.start == list.end { // full
		pos = list.end
		list.end = (list.end + 1) % len(list.buffer)
		list.start = list.end // advance start as well, overwriting first entry
	}

	list.buffer[pos] = whowas
}

// Find tries to find an entry in our WhoWasList with the given details.
func (list *WhoWasList) Find(nickname string, limit int) (results []WhoWas) {
	casefoldedNickname, err := CasefoldName(nickname)
	if err != nil {
		return
	}

	list.accessMutex.RLock()
	defer list.accessMutex.RUnlock()

	if list.start == -1 {
		return
	}
	// iterate backwards through the ring buffer
	pos := list.prev(list.end)
	for limit == 0 || len(results) < limit {
		if casefoldedNickname == list.buffer[pos].nickCasefolded {
			results = append(results, list.buffer[pos])
		}
		if pos == list.start {
			break
		}
		pos = list.prev(pos)
	}

	return
}

func (list *WhoWasList) prev(index int) int {
	switch index {
	case 0:
		return len(list.buffer) - 1
	default:
		return index - 1
	}
}
