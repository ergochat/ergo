// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/goshuirc/irc-go/ircmatch"
	"github.com/oragono/oragono/irc/caps"

	"sync"
)

var (
	ErrNickMissing      = errors.New("nick missing")
	ErrNicknameInUse    = errors.New("nickname in use")
	ErrNicknameMismatch = errors.New("nickname mismatch")
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

// ClientLookupSet represents a way to store, search and lookup clients.
type ClientLookupSet struct {
	ByNickMutex sync.RWMutex
	ByNick      map[string]*Client
}

// NewClientLookupSet returns a new lookup set.
func NewClientLookupSet() *ClientLookupSet {
	return &ClientLookupSet{
		ByNick: make(map[string]*Client),
	}
}

// Count returns how many clients are in the lookup set.
func (clients *ClientLookupSet) Count() int {
	clients.ByNickMutex.RLock()
	defer clients.ByNickMutex.RUnlock()
	count := len(clients.ByNick)
	return count
}

// Has returns whether or not the given client exists.
//TODO(dan): This seems like ripe ground for a race, if code does Has then Get, and assumes the Get will return a client.
func (clients *ClientLookupSet) Has(nick string) bool {
	casefoldedName, err := CasefoldName(nick)
	if err == nil {
		return false
	}
	clients.ByNickMutex.RLock()
	defer clients.ByNickMutex.RUnlock()
	_, exists := clients.ByNick[casefoldedName]
	return exists
}

// getNoMutex is used internally, for getting clients when no mutex is required (i.e. is already set).
func (clients *ClientLookupSet) getNoMutex(nick string) *Client {
	casefoldedName, err := CasefoldName(nick)
	if err == nil {
		cli := clients.ByNick[casefoldedName]
		return cli
	}
	return nil
}

// Get retrieves a client from the set, if they exist.
func (clients *ClientLookupSet) Get(nick string) *Client {
	casefoldedName, err := CasefoldName(nick)
	if err == nil {
		clients.ByNickMutex.RLock()
		defer clients.ByNickMutex.RUnlock()
		cli := clients.ByNick[casefoldedName]
		return cli
	}
	return nil
}

// Add adds a client to the lookup set.
func (clients *ClientLookupSet) Add(client *Client, nick string) error {
	nick, err := CasefoldName(nick)
	if err != nil {
		return err
	}
	clients.ByNickMutex.Lock()
	defer clients.ByNickMutex.Unlock()
	if clients.getNoMutex(nick) != nil {
		return ErrNicknameInUse
	}
	clients.ByNick[nick] = client
	return nil
}

// Remove removes a client from the lookup set.
func (clients *ClientLookupSet) Remove(client *Client) error {
	if !client.HasNick() {
		return ErrNickMissing
	}
	clients.ByNickMutex.Lock()
	defer clients.ByNickMutex.Unlock()
	if clients.getNoMutex(client.nick) != client {
		return ErrNicknameMismatch
	}
	delete(clients.ByNick, client.nickCasefolded)
	return nil
}

// Replace renames an existing client in the lookup set.
func (clients *ClientLookupSet) Replace(oldNick, newNick string, client *Client) error {
	// get casefolded nicknames
	oldNick, err := CasefoldName(oldNick)
	if err != nil {
		return err
	}
	newNick, err = CasefoldName(newNick)
	if err != nil {
		return err
	}

	// remove and replace
	clients.ByNickMutex.Lock()
	defer clients.ByNickMutex.Unlock()

	oldClient := clients.ByNick[newNick]
	if oldClient == nil || oldClient == client {
		// whoo
	} else {
		return ErrNicknameInUse
	}

	if oldNick == newNick {
		// if they're only changing case, don't need to remove+re-add them
		return nil
	}

	delete(clients.ByNick, oldNick)
	clients.ByNick[newNick] = client
	return nil
}

// AllWithCaps returns all clients with the given capabilities.
func (clients *ClientLookupSet) AllWithCaps(caps ...caps.Capability) (set ClientSet) {
	set = make(ClientSet)

	clients.ByNickMutex.RLock()
	defer clients.ByNickMutex.RUnlock()
	var client *Client
	for _, client = range clients.ByNick {
		// make sure they have all the required caps
		for _, Cap := range caps {
			if !client.capabilities[Cap] {
				continue
			}
		}

		set.Add(client)
	}

	return set
}

// FindAll returns all clients that match the given userhost mask.
func (clients *ClientLookupSet) FindAll(userhost string) (set ClientSet) {
	set = make(ClientSet)

	userhost, err := Casefold(ExpandUserHost(userhost))
	if err != nil {
		return set
	}
	matcher := ircmatch.MakeMatch(userhost)

	clients.ByNickMutex.RLock()
	defer clients.ByNickMutex.RUnlock()
	for _, client := range clients.ByNick {
		if matcher.Match(client.nickMaskCasefolded) {
			set.Add(client)
		}
	}

	return set
}

// Find returns the first client that matches the given userhost mask.
func (clients *ClientLookupSet) Find(userhost string) *Client {
	userhost, err := Casefold(ExpandUserHost(userhost))
	if err != nil {
		return nil
	}
	matcher := ircmatch.MakeMatch(userhost)
	var matchedClient *Client

	clients.ByNickMutex.RLock()
	defer clients.ByNickMutex.RUnlock()
	for _, client := range clients.ByNick {
		if matcher.Match(client.nickMaskCasefolded) {
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
type UserMaskSet struct {
	masks  map[string]bool
	regexp *regexp.Regexp
}

func NewUserMaskSet() *UserMaskSet {
	return &UserMaskSet{
		masks: make(map[string]bool),
	}
}

func (set *UserMaskSet) Add(mask string) bool {
	casefoldedMask, err := Casefold(mask)
	if err != nil {
		log.Println(fmt.Sprintf("ERROR: Could not add mask to usermaskset: [%s]", mask))
		return false
	}
	if set.masks[casefoldedMask] {
		return false
	}
	set.masks[casefoldedMask] = true
	set.setRegexp()
	return true
}

func (set *UserMaskSet) AddAll(masks []string) (added bool) {
	for _, mask := range masks {
		if !added && !set.masks[mask] {
			added = true
		}
		set.masks[mask] = true
	}
	set.setRegexp()
	return
}

func (set *UserMaskSet) Remove(mask string) bool {
	if !set.masks[mask] {
		return false
	}
	delete(set.masks, mask)
	set.setRegexp()
	return true
}

func (set *UserMaskSet) Match(userhost string) bool {
	if set.regexp == nil {
		return false
	}
	return set.regexp.MatchString(userhost)
}

func (set *UserMaskSet) String() string {
	masks := make([]string, len(set.masks))
	index := 0
	for mask := range set.masks {
		masks[index] = mask
		index += 1
	}
	return strings.Join(masks, " ")
}

// Generate a regular expression from the set of user mask
// strings. Masks are split at the two types of wildcards, `*` and
// `?`. All the pieces are meta-escaped. `*` is replaced with `.*`,
// the regexp equivalent. Likewise, `?` is replaced with `.`. The
// parts are re-joined and finally all masks are joined into a big
// or-expression.
func (set *UserMaskSet) setRegexp() {
	if len(set.masks) == 0 {
		set.regexp = nil
		return
	}

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
	}
	expr := "^" + strings.Join(maskExprs, "|") + "$"
	set.regexp, _ = regexp.Compile(expr)
}
