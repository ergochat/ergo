// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"sync"
)

// WhoWasList holds our list of prior clients (for use with the WHOWAS command).
type WhoWasList struct {
	buffer []*WhoWas
	start  int
	end    int

	accessMutex sync.RWMutex // tier 2
}

// WhoWas is an entry in the WhoWasList.
type WhoWas struct {
	nicknameCasefolded string
	nickname           string
	username           string
	hostname           string
	realname           string
}

// NewWhoWasList returns a new WhoWasList
func NewWhoWasList(size uint) *WhoWasList {
	return &WhoWasList{
		buffer: make([]*WhoWas, size+1),
	}
}

// Append adds an entry to the WhoWasList.
func (list *WhoWasList) Append(client *Client) {
	list.accessMutex.Lock()
	defer list.accessMutex.Unlock()

	list.buffer[list.end] = &WhoWas{
		nicknameCasefolded: client.nickCasefolded,
		nickname:           client.nick,
		username:           client.username,
		hostname:           client.hostname,
		realname:           client.realname,
	}
	list.end = (list.end + 1) % len(list.buffer)
	if list.end == list.start {
		list.start = (list.end + 1) % len(list.buffer)
	}
}

// Find tries to find an entry in our WhoWasList with the given details.
func (list *WhoWasList) Find(nickname string, limit int64) []*WhoWas {
	list.accessMutex.RLock()
	defer list.accessMutex.RUnlock()

	results := make([]*WhoWas, 0)

	casefoldedNickname, err := CasefoldName(nickname)
	if err != nil {
		return results
	}

	for whoWas := range list.Each() {
		if casefoldedNickname != whoWas.nicknameCasefolded {
			continue
		}
		results = append(results, whoWas)
		if int64(len(results)) >= limit {
			break
		}
	}
	return results
}

func (list *WhoWasList) prev(index int) int {
	list.accessMutex.RLock()
	defer list.accessMutex.RUnlock()

	index--
	if index < 0 {
		index += len(list.buffer)
	}
	return index
}

// Each iterates the WhoWasList in reverse.
func (list *WhoWasList) Each() <-chan *WhoWas {
	ch := make(chan *WhoWas)
	go func() {
		defer close(ch)
		if list.start == list.end {
			return
		}
		start := list.prev(list.end)
		end := list.prev(list.start)
		for start != end {
			ch <- list.buffer[start]
			start = list.prev(start)
		}
	}()
	return ch
}
