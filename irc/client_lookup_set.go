// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"strings"
	"sync"

	"github.com/ergochat/ergo/irc/caps"
	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/utils"
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

func (clients *ClientManager) removeInternal(client *Client, oldcfnick, oldskeleton string) (err error) {
	// requires holding the writable Lock()
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

	oldcfnick, oldskeleton := client.uniqueIdentifiers()
	return clients.removeInternal(client, oldcfnick, oldskeleton)
}

// SetNick sets a client's nickname, validating it against nicknames in use
// XXX: dryRun validates a client's ability to claim a nick, without
// actually claiming it
func (clients *ClientManager) SetNick(client *Client, session *Session, newNick string, dryRun bool) (setNick string, err error, returnedFromAway bool) {
	config := client.server.Config()

	var newCfNick, newSkeleton string

	client.stateMutex.RLock()
	account := client.account
	accountName := client.accountName
	settings := client.accountSettings
	registered := client.registered
	realname := client.realname
	client.stateMutex.RUnlock()

	// these restrictions have grandfather exceptions for nicknames registered
	// on previous versions of Ergo:
	if newNick != accountName {
		// can't contain "disfavored" characters like <, or start with a $ because
		// it collides with the massmessage mask syntax. '0' conflicts with the use of 0
		// as a placeholder in WHOX (#1896):
		if strings.ContainsAny(newNick, disfavoredNameCharacters) || strings.HasPrefix(newNick, "$") ||
			newNick == "0" {
			return "", errNicknameInvalid, false
		}
	}

	// recompute always-on status, because client.alwaysOn is not set for unregistered clients
	var alwaysOn, useAccountName bool
	if account != "" {
		alwaysOn = persistenceEnabled(config.Accounts.Multiclient.AlwaysOn, settings.AlwaysOn)
		useAccountName = alwaysOn || config.Accounts.NickReservation.ForceNickEqualsAccount
	}

	if useAccountName {
		if registered && newNick != accountName {
			return "", errNickAccountMismatch, false
		}
		newNick = accountName
		newCfNick = account
		newSkeleton, err = Skeleton(newNick)
		if err != nil {
			return "", errNicknameInvalid, false
		}
	} else {
		newNick = strings.TrimSpace(newNick)
		if len(newNick) == 0 {
			return "", errNickMissing, false
		}

		if account == "" && config.Accounts.NickReservation.ForceGuestFormat && !dryRun {
			newCfNick, err = CasefoldName(newNick)
			if err != nil {
				return "", errNicknameInvalid, false
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
			return "", errNicknameInvalid, false
		}
		if len(newNick) > config.Limits.NickLen || len(newCfNick) > config.Limits.NickLen {
			return "", errNicknameInvalid, false
		}
		newSkeleton, err = Skeleton(newNick)
		if err != nil {
			return "", errNicknameInvalid, false
		}

		if config.isRelaymsgIdentifier(newNick) {
			return "", errNicknameInvalid, false
		}

		if restrictedCasefoldedNicks.Has(newCfNick) || restrictedSkeletons.Has(newSkeleton) {
			return "", errNicknameInvalid, false
		}

		reservedAccount, method := client.server.accounts.EnforcementStatus(newCfNick, newSkeleton)
		if method == NickEnforcementStrict && reservedAccount != "" && reservedAccount != account {
			return "", errNicknameReserved, false
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
	if currentClient != nil && currentClient != client {
		// these conditions forbid reattaching to an existing session:
		if registered || !bouncerAllowed || account == "" || account != currentClient.Account() ||
			dryRun || session == nil {
			return "", errNicknameInUse, false
		}
		// check TLS modes
		if client.HasMode(modes.TLS) != currentClient.HasMode(modes.TLS) {
			if useAccountName {
				// #955: this is fatal because they can't fix it by trying a different nick
				return "", errInsecureReattach, false
			} else {
				return "", errNicknameInUse, false
			}
		}
		reattachSuccessful, numSessions, lastSeen, back := currentClient.AddSession(session)
		if !reattachSuccessful {
			return "", errNicknameInUse, false
		}
		if numSessions == 1 {
			invisible := currentClient.HasMode(modes.Invisible)
			operator := currentClient.HasMode(modes.Operator)
			client.server.stats.AddRegistered(invisible, operator)
		}
		session.autoreplayMissedSince = lastSeen
		// TODO: transition mechanism for #1065, clean this up eventually:
		if currentClient.Realname() == "" {
			currentClient.SetRealname(realname)
		}
		// successful reattach!
		return newNick, nil, back
	} else if currentClient == client && currentClient.Nick() == newNick {
		return "", errNoop, false
	}
	// analogous checks for skeletons
	skeletonHolder := clients.bySkeleton[newSkeleton]
	if skeletonHolder != nil && skeletonHolder != client {
		return "", errNicknameInUse, false
	}

	if dryRun {
		return "", nil, false
	}

	formercfnick, formerskeleton := client.uniqueIdentifiers()
	if changeSuccess := client.SetNick(newNick, newCfNick, newSkeleton); !changeSuccess {
		return "", errClientDestroyed, false
	}
	clients.removeInternal(client, formercfnick, formerskeleton)
	clients.byNick[newCfNick] = client
	clients.bySkeleton[newSkeleton] = client
	return newNick, nil, false
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

// Determine the canonical / unfolded form of a nick, if a client matching it
// is present (or always-on).
func (clients *ClientManager) UnfoldNick(cfnick string) (nick string) {
	clients.RLock()
	c := clients.byNick[cfnick]
	clients.RUnlock()
	if c != nil {
		return c.Nick()
	} else {
		return cfnick
	}
}
