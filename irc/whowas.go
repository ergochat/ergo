// Copyright (c) 2012-2014 Jeremy Latt
// released under the MIT license

package irc

type WhoWasList struct {
	buffer []*WhoWas
	start  int
	end    int
}

type WhoWas struct {
	nickname Name
	username Name
	hostname Name
	realname Text
}

func NewWhoWasList(size uint) *WhoWasList {
	return &WhoWasList{
		buffer: make([]*WhoWas, size),
	}
}

func (list *WhoWasList) Append(client *Client) {
	list.buffer[list.end] = &WhoWas{
		nickname: client.Nick(),
		username: client.username,
		hostname: client.hostname,
		realname: client.realname,
	}
	list.end = (list.end + 1) % len(list.buffer)
	if list.end == list.start {
		list.start = (list.end + 1) % len(list.buffer)
	}
}

func (list *WhoWasList) Find(nickname Name, limit int64) []*WhoWas {
	results := make([]*WhoWas, 0)
	for whoWas := range list.Each() {
		if nickname != whoWas.nickname {
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
