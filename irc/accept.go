package irc

import (
	"sync"

	"github.com/ergochat/ergo/irc/utils"
)

// tracks ACCEPT relationships, i.e., `accepter` is willing to receive DMs from
// `accepted` despite some restriction (currently the only relevant restriction
// is that `accepter` is +R and `accepted` is not logged in)

type AcceptManager struct {
	sync.RWMutex

	// maps recipient -> whitelist of permitted senders:
	// this is what we actually check
	clientToAccepted map[*Client]utils.HashSet[*Client]
	// this is the reverse mapping, it's needed so we can
	// clean up the forward mapping during (*Client).destroy():
	clientToAccepters map[*Client]utils.HashSet[*Client]
}

func (am *AcceptManager) Initialize() {
	am.clientToAccepted = make(map[*Client]utils.HashSet[*Client])
	am.clientToAccepters = make(map[*Client]utils.HashSet[*Client])
}

func (am *AcceptManager) MaySendTo(sender, recipient *Client) (result bool) {
	am.RLock()
	defer am.RUnlock()
	return am.clientToAccepted[recipient].Has(sender)
}

func (am *AcceptManager) Accept(accepter, accepted *Client) {
	am.Lock()
	defer am.Unlock()

	var m utils.HashSet[*Client]

	m = am.clientToAccepted[accepter]
	if m == nil {
		m = make(utils.HashSet[*Client])
		am.clientToAccepted[accepter] = m
	}
	m.Add(accepted)

	m = am.clientToAccepters[accepted]
	if m == nil {
		m = make(utils.HashSet[*Client])
		am.clientToAccepters[accepted] = m
	}
	m.Add(accepter)
}

func (am *AcceptManager) Unaccept(accepter, accepted *Client) {
	am.Lock()
	defer am.Unlock()

	delete(am.clientToAccepted[accepter], accepted)
	delete(am.clientToAccepters[accepted], accepter)
}

func (am *AcceptManager) Remove(client *Client) {
	am.Lock()
	defer am.Unlock()

	for accepter := range am.clientToAccepters[client] {
		delete(am.clientToAccepted[accepter], client)
	}
	for accepted := range am.clientToAccepted[client] {
		delete(am.clientToAccepters[accepted], client)
	}
	delete(am.clientToAccepters, client)
	delete(am.clientToAccepted, client)
}
