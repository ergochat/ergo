// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

type WhoWasList struct {
	buffer []*WhoWas
	start  int
	end    int
}

type WhoWas struct {
	nicknameCasefolded string
	nickname           string
	username           string
	hostname           string
	realname           string
}

func NewWhoWasList(size uint) *WhoWasList {
	return &WhoWasList{
		buffer: make([]*WhoWas, size+1),
	}
}

func (list *WhoWasList) Append(client *Client) {
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

func (list *WhoWasList) Find(nickname string, limit int64) []*WhoWas {
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
	index -= 1
	if index < 0 {
		index += len(list.buffer)
	}
	return index
}

// Iterate the buffer in reverse.
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
