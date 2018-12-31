// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/goshuirc/irc-go/ircmatch"
	"github.com/oragono/oragono/irc/caps"

	"sync"
)

// ExpandUserHost takes a userhost, and returns an expanded version.
func ExpandUserHost(userhost string) (expanded string) {
	expanded = userhost
	// fill in missing wildcards for nicks
	//TODO(dan): this would fail with dan@lol, fix that.
	if !strings.Contains(expanded, "!") {
		expanded += "!*"
	}
	if !strings.Contains(expanded, "@") {
		expanded += "@*"
	}
	return
}

// ClientManager keeps track of clients by nick, enforcing uniqueness of casefolded nicks
type ClientManager struct {
	sync.RWMutex // tier 2
	byNick       map[string]*Client
}

// NewClientManager returns a new ClientManager.
func NewClientManager() *ClientManager {
	return &ClientManager{
		byNick: make(map[string]*Client),
	}
}

// Count returns how many clients are in the manager.
func (clients *ClientManager) Count() int {
	clients.RLock()
	defer clients.RUnlock()
	count := len(clients.byNick)
	return count
}

// Get retrieves a client from the manager, if they exist.
func (clients *ClientManager) Get(nick string) *Client {
	casefoldedName, err := CasefoldName(nick)
	if err == nil {
		clients.RLock()
		defer clients.RUnlock()
		cli := clients.byNick[casefoldedName]
		return cli
	}
	return nil
}

func (clients *ClientManager) removeInternal(client *Client) (err error) {
	// requires holding the writable Lock()
	oldcfnick := client.NickCasefolded()
	currentEntry, present := clients.byNick[oldcfnick]
	if present {
		if currentEntry == client {
			delete(clients.byNick, oldcfnick)
		} else {
			// this shouldn't happen, but we can ignore it
			client.server.logger.Warning("internal", fmt.Sprintf("clients for nick %s out of sync", oldcfnick))
			err = errNickMissing
		}
	}
	return
}

// Remove removes a client from the lookup set.
func (clients *ClientManager) Remove(client *Client) error {
	clients.Lock()
	defer clients.Unlock()

	if !client.HasNick() {
		return errNickMissing
	}
	return clients.removeInternal(client)
}

// Resume atomically replaces `oldClient` with `newClient`, updating
// newClient's data to match. It is the caller's responsibility first
// to verify that the resume is allowed, and then later to call oldClient.destroy().
func (clients *ClientManager) Resume(newClient, oldClient *Client) (err error) {
	clients.Lock()
	defer clients.Unlock()

	// atomically grant the new client the old nick
	err = clients.removeInternal(oldClient)
	if err != nil {
		// oldClient no longer owns its nick, fail out
		return err
	}
	// nick has been reclaimed, grant it to the new client
	clients.removeInternal(newClient)
	clients.byNick[oldClient.NickCasefolded()] = newClient

	newClient.copyResumeData(oldClient)

	return nil
}

// SetNick sets a client's nickname, validating it against nicknames in use
func (clients *ClientManager) SetNick(client *Client, newNick string) error {
	newcfnick, err := CasefoldName(newNick)
	if err != nil {
		return err
	}

	var reservedAccount string
	var method NickReservationMethod
	if client.server.AccountConfig().NickReservation.Enabled {
		reservedAccount = client.server.accounts.NickToAccount(newcfnick)
		method = client.server.AccountConfig().NickReservation.Method
	}

	clients.Lock()
	defer clients.Unlock()

	clients.removeInternal(client)
	currentNewEntry := clients.byNick[newcfnick]
	// the client may just be changing case
	if currentNewEntry != nil && currentNewEntry != client {
		return errNicknameInUse
	}
	if method == NickReservationStrict && reservedAccount != client.Account() {
		return errNicknameReserved
	}
	clients.byNick[newcfnick] = client
	client.updateNickMask(newNick)
	return nil
}

func (clients *ClientManager) AllClients() (result []*Client) {
	clients.RLock()
	defer clients.RUnlock()
	result = make([]*Client, len(clients.byNick))
	i := 0
	for _, client := range clients.byNick {
		result[i] = client
		i++
	}
	return
}

// AllWithCaps returns all clients with the given capabilities.
func (clients *ClientManager) AllWithCaps(capabs ...caps.Capability) (set ClientSet) {
	set = make(ClientSet)

	clients.RLock()
	defer clients.RUnlock()
	var client *Client
	for _, client = range clients.byNick {
		// make sure they have all the required caps
		for _, capab := range capabs {
			if !client.capabilities.Has(capab) {
				continue
			}
		}

		set.Add(client)
	}

	return set
}

// FindAll returns all clients that match the given userhost mask.
func (clients *ClientManager) FindAll(userhost string) (set ClientSet) {
	set = make(ClientSet)

	userhost, err := Casefold(ExpandUserHost(userhost))
	if err != nil {
		return set
	}
	matcher := ircmatch.MakeMatch(userhost)

	clients.RLock()
	defer clients.RUnlock()
	for _, client := range clients.byNick {
		if matcher.Match(client.NickMaskCasefolded()) {
			set.Add(client)
		}
	}

	return set
}

// Find returns the first client that matches the given userhost mask.
func (clients *ClientManager) Find(userhost string) *Client {
	userhost, err := Casefold(ExpandUserHost(userhost))
	if err != nil {
		return nil
	}
	matcher := ircmatch.MakeMatch(userhost)
	var matchedClient *Client

	clients.RLock()
	defer clients.RUnlock()
	for _, client := range clients.byNick {
		if matcher.Match(client.NickMaskCasefolded()) {
			matchedClient = client
			break
		}
	}

	return matchedClient
}

//
// usermask to regexp
//

//TODO(dan): move this over to generally using glob syntax instead?
// kinda more expected in normal ban/etc masks, though regex is useful (probably as an extban?)

// UserMaskSet holds a set of client masks and lets you match  hostnames to them.
type UserMaskSet struct {
	sync.RWMutex
	masks  map[string]bool
	regexp *regexp.Regexp
}

// NewUserMaskSet returns a new UserMaskSet.
func NewUserMaskSet() *UserMaskSet {
	return &UserMaskSet{
		masks: make(map[string]bool),
	}
}

// Add adds the given mask to this set.
func (set *UserMaskSet) Add(mask string) (added bool) {
	casefoldedMask, err := Casefold(mask)
	if err != nil {
		log.Println(fmt.Sprintf("ERROR: Could not add mask to usermaskset: [%s]", mask))
		return false
	}

	set.Lock()
	added = !set.masks[casefoldedMask]
	if added {
		set.masks[casefoldedMask] = true
	}
	set.Unlock()

	if added {
		set.setRegexp()
	}
	return
}

// AddAll adds the given masks to this set.
func (set *UserMaskSet) AddAll(masks []string) (added bool) {
	set.Lock()
	defer set.Unlock()

	for _, mask := range masks {
		if !added && !set.masks[mask] {
			added = true
		}
		set.masks[mask] = true
	}
	if added {
		set.setRegexp()
	}
	return
}

// Remove removes the given mask from this set.
func (set *UserMaskSet) Remove(mask string) (removed bool) {
	set.Lock()
	removed = set.masks[mask]
	if removed {
		delete(set.masks, mask)
	}
	set.Unlock()

	if removed {
		set.setRegexp()
	}
	return
}

// Match matches the given n!u@h.
func (set *UserMaskSet) Match(userhost string) bool {
	set.RLock()
	regexp := set.regexp
	set.RUnlock()

	if regexp == nil {
		return false
	}
	return regexp.MatchString(userhost)
}

// String returns the masks in this set.
func (set *UserMaskSet) String() string {
	set.RLock()
	masks := make([]string, len(set.masks))
	index := 0
	for mask := range set.masks {
		masks[index] = mask
		index++
	}
	set.RUnlock()
	return strings.Join(masks, " ")
}

func (set *UserMaskSet) Length() int {
	set.RLock()
	defer set.RUnlock()
	return len(set.masks)
}

// setRegexp generates a regular expression from the set of user mask
// strings. Masks are split at the two types of wildcards, `*` and
// `?`. All the pieces are meta-escaped. `*` is replaced with `.*`,
// the regexp equivalent. Likewise, `?` is replaced with `.`. The
// parts are re-joined and finally all masks are joined into a big
// or-expression.
func (set *UserMaskSet) setRegexp() {
	var re *regexp.Regexp

	set.RLock()
	maskExprs := make([]string, len(set.masks))
	index := 0
	for mask := range set.masks {
		manyParts := strings.Split(mask, "*")
		manyExprs := make([]string, len(manyParts))
		for mindex, manyPart := range manyParts {
			oneParts := strings.Split(manyPart, "?")
			oneExprs := make([]string, len(oneParts))
			for oindex, onePart := range oneParts {
				oneExprs[oindex] = regexp.QuoteMeta(onePart)
			}
			manyExprs[mindex] = strings.Join(oneExprs, ".")
		}
		maskExprs[index] = strings.Join(manyExprs, ".*")
		index++
	}
	set.RUnlock()

	if index > 0 {
		expr := "^" + strings.Join(maskExprs, "|") + "$"
		re, _ = regexp.Compile(expr)
	}

	set.Lock()
	set.regexp = re
	set.Unlock()
}
