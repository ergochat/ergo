package irc

import (
	"fmt"
	"sync"

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/oragono/oragono/irc/sno"
)

// SnoManager keeps track of which clients to send snomasks to.
type SnoManager struct {
	sendListMutex sync.RWMutex // tier 2
	sendLists     map[sno.Mask]map[*Client]bool
}

func (m *SnoManager) Initialize() {
	m.sendLists = make(map[sno.Mask]map[*Client]bool)
}

// AddMasks adds the given snomasks to the client.
func (m *SnoManager) AddMasks(client *Client, masks ...sno.Mask) {
	m.sendListMutex.Lock()
	defer m.sendListMutex.Unlock()

	for _, mask := range masks {
		currentClientList := m.sendLists[mask]

		if currentClientList == nil {
			currentClientList = map[*Client]bool{}
		}

		currentClientList[client] = true

		m.sendLists[mask] = currentClientList
	}
}

// RemoveMasks removes the given snomasks from the client.
func (m *SnoManager) RemoveMasks(client *Client, masks ...sno.Mask) {
	m.sendListMutex.Lock()
	defer m.sendListMutex.Unlock()

	for _, mask := range masks {
		currentClientList := m.sendLists[mask]

		if len(currentClientList) == 0 {
			continue
		}

		delete(currentClientList, client)

		m.sendLists[mask] = currentClientList
	}
}

// RemoveClient removes the given client from all of our lists.
func (m *SnoManager) RemoveClient(client *Client) {
	m.sendListMutex.Lock()
	defer m.sendListMutex.Unlock()

	for mask := range m.sendLists {
		currentClientList := m.sendLists[mask]

		if len(currentClientList) == 0 {
			continue
		}

		delete(currentClientList, client)

		m.sendLists[mask] = currentClientList
	}
}

// Send sends the given snomask to all users signed up for it.
func (m *SnoManager) Send(mask sno.Mask, content string) {
	m.sendListMutex.RLock()
	defer m.sendListMutex.RUnlock()

	currentClientList := m.sendLists[mask]

	if len(currentClientList) == 0 {
		return
	}

	// make the message
	name := sno.NoticeMaskNames[mask]
	if name == "" {
		name = string(mask)
	}
	message := fmt.Sprintf(ircfmt.Unescape("$c[grey]-$r%s$c[grey]-$c %s"), name, content)

	// send it out
	for client := range currentClientList {
		client.Notice(message)
	}
}

// MasksEnabled returns the snomasks currently enabled.
func (m *SnoManager) MasksEnabled(client *Client) (result sno.Masks) {
	m.sendListMutex.RLock()
	defer m.sendListMutex.RUnlock()

	for mask, clients := range m.sendLists {
		for c := range clients {
			if c == client {
				result = append(result, mask)
				break
			}
		}
	}
	return
}

func (m *SnoManager) String(client *Client) string {
	masks := m.MasksEnabled(client)
	return masks.String()
}
