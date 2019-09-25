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
	"github.com/oragono/oragono/irc/modes"

	"sync"
)

// ClientManager keeps track of clients by nick, enforcing uniqueness of casefolded nicks
type ClientManager struct {
	sync.RWMutex // tier 2
	byNick       map[string]*Client
	bySkeleton   map[string]*Client
}

// Initialize initializes a ClientManager.
func (clients *ClientManager) Initialize() {
	clients.byNick = make(map[string]*Client)
	clients.bySkeleton = make(map[string]*Client)
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
	oldcfnick, oldskeleton := client.uniqueIdentifiers()
	if oldcfnick == "*" || oldcfnick == "" {
		return errNickMissing
	}

	currentEntry, present := clients.byNick[oldcfnick]
	if present {
		if currentEntry == client {
			delete(clients.byNick, oldcfnick)
		} else {
			// this shouldn't happen, but we can ignore it
			client.server.logger.Warning("internal", "clients for nick out of sync", oldcfnick)
			err = errNickMissing
		}
	} else {
		err = errNickMissing
	}

	currentEntry, present = clients.bySkeleton[oldskeleton]
	if present {
		if currentEntry == client {
			delete(clients.bySkeleton, oldskeleton)
		} else {
			client.server.logger.Warning("internal", "clients for skeleton out of sync", oldskeleton)
			err = errNickMissing
		}
	} else {
		err = errNickMissing
	}

	return
}

// Remove removes a client from the lookup set.
func (clients *ClientManager) Remove(client *Client) error {
	clients.Lock()
	defer clients.Unlock()

	return clients.removeInternal(client)
}

// Handles a RESUME by attaching a session to a designated client. It is the
// caller's responsibility to verify that the resume is allowed (checking tokens,
// TLS status, etc.) before calling this.
func (clients *ClientManager) Resume(oldClient *Client, session *Session) (err error) {
	clients.Lock()
	defer clients.Unlock()

	cfnick := oldClient.NickCasefolded()
	if _, ok := clients.byNick[cfnick]; !ok {
		return errNickMissing
	}

	if !oldClient.AddSession(session) {
		return errNickMissing
	}

	return nil
}

// SetNick sets a client's nickname, validating it against nicknames in use
func (clients *ClientManager) SetNick(client *Client, session *Session, newNick string) error {
	if len(newNick) > client.server.Config().Limits.NickLen {
		return errNicknameInvalid
	}
	newcfnick, err := CasefoldName(newNick)
	if err != nil {
		return errNicknameInvalid
	}
	newSkeleton, err := Skeleton(newNick)
	if err != nil {
		return errNicknameInvalid
	}

	if restrictedCasefoldedNicks[newcfnick] || restrictedSkeletons[newSkeleton] {
		return errNicknameInvalid
	}

	reservedAccount, method := client.server.accounts.EnforcementStatus(newcfnick, newSkeleton)
	account := client.Account()
	config := client.server.Config()
	var bouncerAllowed bool
	if config.Accounts.Bouncer.Enabled {
		if session != nil && session.capabilities.Has(caps.Bouncer) {
			bouncerAllowed = true
		} else {
			settings := client.AccountSettings()
			if config.Accounts.Bouncer.AllowedByDefault && settings.AllowBouncer != BouncerDisallowedByUser {
				bouncerAllowed = true
			} else if settings.AllowBouncer == BouncerAllowedByUser {
				bouncerAllowed = true
			}
		}
	}

	clients.Lock()
	defer clients.Unlock()

	currentClient := clients.byNick[newcfnick]
	// the client may just be changing case
	if currentClient != nil && currentClient != client && session != nil {
		// these conditions forbid reattaching to an existing session:
		if client.Registered() || !bouncerAllowed || account == "" || account != currentClient.Account() || client.HasMode(modes.TLS) != currentClient.HasMode(modes.TLS) {
			return errNicknameInUse
		}
		if !currentClient.AddSession(session) {
			return errNicknameInUse
		}
		// successful reattach!
		return nil
	}
	// analogous checks for skeletons
	skeletonHolder := clients.bySkeleton[newSkeleton]
	if skeletonHolder != nil && skeletonHolder != client {
		return errNicknameInUse
	}
	if method == NickEnforcementStrict && reservedAccount != "" && reservedAccount != account {
		return errNicknameReserved
	}
	clients.removeInternal(client)
	clients.byNick[newcfnick] = client
	clients.bySkeleton[newSkeleton] = client
	client.updateNick(newNick, newcfnick, newSkeleton)
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
func (clients *ClientManager) AllWithCaps(capabs ...caps.Capability) (sessions []*Session) {
	clients.RLock()
	defer clients.RUnlock()
	for _, client := range clients.byNick {
		for _, session := range client.Sessions() {
			if session.capabilities.HasAll(capabs...) {
				sessions = append(sessions, session)
			}
		}
	}

	return
}

// AllWithCapsNotify returns all clients with the given capabilities, and that support cap-notify.
func (clients *ClientManager) AllWithCapsNotify(capabs ...caps.Capability) (sessions []*Session) {
	capabs = append(capabs, caps.CapNotify)
	clients.RLock()
	defer clients.RUnlock()
	for _, client := range clients.byNick {
		for _, session := range client.Sessions() {
			// cap-notify is implicit in cap version 302 and above
			if session.capabilities.HasAll(capabs...) || 302 <= session.capVersion {
				sessions = append(sessions, session)
			}
		}
	}

	return
}

// FindAll returns all clients that match the given userhost mask.
func (clients *ClientManager) FindAll(userhost string) (set ClientSet) {
	set = make(ClientSet)

	userhost, err := CanonicalizeMaskWildcard(userhost)
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
