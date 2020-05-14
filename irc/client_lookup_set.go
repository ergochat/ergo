// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/oragono/oragono/irc/caps"
	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/utils"
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

	success, _, _ := oldClient.AddSession(session)
	if !success {
		return errNickMissing
	}

	return nil
}

// SetNick sets a client's nickname, validating it against nicknames in use
func (clients *ClientManager) SetNick(client *Client, session *Session, newNick string) (setNick string, err error) {
	config := client.server.Config()

	var newCfNick, newSkeleton string

	client.stateMutex.RLock()
	account := client.account
	accountName := client.accountName
	settings := client.accountSettings
	registered := client.registered
	realname := client.realname
	client.stateMutex.RUnlock()

	// recompute always-on status, because client.alwaysOn is not set for unregistered clients
	var alwaysOn, useAccountName bool
	if account != "" {
		alwaysOn = persistenceEnabled(config.Accounts.Multiclient.AlwaysOn, settings.AlwaysOn)
		useAccountName = alwaysOn || config.Accounts.NickReservation.ForceNickEqualsAccount
	}

	if useAccountName {
		if registered && newNick != accountName && newNick != "" {
			return "", errNickAccountMismatch
		}
		newNick = accountName
		newCfNick = account
		newSkeleton, err = Skeleton(newNick)
		if err != nil {
			return "", errNicknameInvalid
		}
	} else {
		newNick = strings.TrimSpace(newNick)
		if len(newNick) == 0 {
			return "", errNickMissing
		}

		if account == "" && config.Accounts.NickReservation.ForceGuestFormat {
			newCfNick, err = CasefoldName(newNick)
			if err != nil {
				return "", errNicknameInvalid
			}
			if !config.Accounts.NickReservation.guestRegexpFolded.MatchString(newCfNick) {
				newNick = strings.Replace(config.Accounts.NickReservation.GuestFormat, "*", newNick, 1)
				newCfNick = "" // re-fold it below
			}
		}

		if newCfNick == "" {
			newCfNick, err = CasefoldName(newNick)
		}
		if err != nil {
			return "", errNicknameInvalid
		}
		if len(newNick) > config.Limits.NickLen || len(newCfNick) > config.Limits.NickLen {
			return "", errNicknameInvalid
		}
		newSkeleton, err = Skeleton(newNick)
		if err != nil {
			return "", errNicknameInvalid
		}

		if restrictedCasefoldedNicks[newCfNick] || restrictedSkeletons[newSkeleton] {
			return "", errNicknameInvalid
		}

		reservedAccount, method := client.server.accounts.EnforcementStatus(newCfNick, newSkeleton)
		if method == NickEnforcementStrict && reservedAccount != "" && reservedAccount != account {
			return "", errNicknameReserved
		}
	}

	var bouncerAllowed bool
	if config.Accounts.Multiclient.Enabled {
		if useAccountName {
			bouncerAllowed = true
		} else {
			if config.Accounts.Multiclient.AllowedByDefault && settings.AllowBouncer != MulticlientDisallowedByUser {
				bouncerAllowed = true
			} else if settings.AllowBouncer == MulticlientAllowedByUser {
				bouncerAllowed = true
			}
		}
	}

	clients.Lock()
	defer clients.Unlock()

	currentClient := clients.byNick[newCfNick]
	// the client may just be changing case
	if currentClient != nil && currentClient != client && session != nil {
		// these conditions forbid reattaching to an existing session:
		if registered || !bouncerAllowed || account == "" || account != currentClient.Account() {
			return "", errNicknameInUse
		}
		// check TLS modes
		if client.HasMode(modes.TLS) != currentClient.HasMode(modes.TLS) {
			if useAccountName {
				// #955: this is fatal because they can't fix it by trying a different nick
				return "", errInsecureReattach
			} else {
				return "", errNicknameInUse
			}
		}
		reattachSuccessful, numSessions, lastSeen := currentClient.AddSession(session)
		if !reattachSuccessful {
			return "", errNicknameInUse
		}
		if numSessions == 1 {
			invisible := currentClient.HasMode(modes.Invisible)
			operator := currentClient.HasMode(modes.Operator) || currentClient.HasMode(modes.LocalOperator)
			client.server.stats.AddRegistered(invisible, operator)
		}
		session.autoreplayMissedSince = lastSeen
		// XXX SetNames only changes names if they are unset, so the realname change only
		// takes effect on first attach to an always-on client (good), but the user/ident
		// change is always a no-op (bad). we could make user/ident act the same way as
		// realname, but then we'd have to send CHGHOST and i don't want to deal with that
		// for performance reasons
		currentClient.SetNames("user", realname, true)
		// successful reattach!
		return newNick, nil
	}
	// analogous checks for skeletons
	skeletonHolder := clients.bySkeleton[newSkeleton]
	if skeletonHolder != nil && skeletonHolder != client {
		return "", errNicknameInUse
	}

	clients.removeInternal(client)
	clients.byNick[newCfNick] = client
	clients.bySkeleton[newSkeleton] = client
	client.updateNick(newNick, newCfNick, newSkeleton)
	return newNick, nil
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
	matcher, err := utils.CompileGlob(userhost, false)
	if err != nil {
		// not much we can do here
		return
	}

	clients.RLock()
	defer clients.RUnlock()
	for _, client := range clients.byNick {
		if matcher.MatchString(client.NickMaskCasefolded()) {
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

type MaskInfo struct {
	TimeCreated     time.Time
	CreatorNickmask string
	CreatorAccount  string
}

// UserMaskSet holds a set of client masks and lets you match  hostnames to them.
type UserMaskSet struct {
	sync.RWMutex
	serialCacheUpdateMutex sync.Mutex
	masks                  map[string]MaskInfo
	regexp                 *regexp.Regexp
}

func NewUserMaskSet() *UserMaskSet {
	return new(UserMaskSet)
}

// Add adds the given mask to this set.
func (set *UserMaskSet) Add(mask, creatorNickmask, creatorAccount string) (maskAdded string, err error) {
	casefoldedMask, err := CanonicalizeMaskWildcard(mask)
	if err != nil {
		return
	}

	set.serialCacheUpdateMutex.Lock()
	defer set.serialCacheUpdateMutex.Unlock()

	set.Lock()
	if set.masks == nil {
		set.masks = make(map[string]MaskInfo)
	}
	_, present := set.masks[casefoldedMask]
	if !present {
		maskAdded = casefoldedMask
		set.masks[casefoldedMask] = MaskInfo{
			TimeCreated:     time.Now().UTC(),
			CreatorNickmask: creatorNickmask,
			CreatorAccount:  creatorAccount,
		}
	}
	set.Unlock()

	if !present {
		set.setRegexp()
	}
	return
}

// Remove removes the given mask from this set.
func (set *UserMaskSet) Remove(mask string) (maskRemoved string, err error) {
	mask, err = CanonicalizeMaskWildcard(mask)
	if err != nil {
		return
	}

	set.serialCacheUpdateMutex.Lock()
	defer set.serialCacheUpdateMutex.Unlock()

	set.Lock()
	_, removed := set.masks[mask]
	if removed {
		maskRemoved = mask
		delete(set.masks, mask)
	}
	set.Unlock()

	if removed {
		set.setRegexp()
	}
	return
}

func (set *UserMaskSet) SetMasks(masks map[string]MaskInfo) {
	set.Lock()
	set.masks = masks
	set.Unlock()
	set.setRegexp()
}

func (set *UserMaskSet) Masks() (result map[string]MaskInfo) {
	set.RLock()
	defer set.RUnlock()

	result = make(map[string]MaskInfo, len(set.masks))
	for mask, info := range set.masks {
		result[mask] = info
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

func (set *UserMaskSet) Length() int {
	set.RLock()
	defer set.RUnlock()
	return len(set.masks)
}

func (set *UserMaskSet) setRegexp() {
	set.RLock()
	maskExprs := make([]string, len(set.masks))
	for mask := range set.masks {
		maskExprs = append(maskExprs, mask)
	}
	set.RUnlock()

	re, _ := utils.CompileMasks(maskExprs)

	set.Lock()
	set.regexp = re
	set.Unlock()
}
