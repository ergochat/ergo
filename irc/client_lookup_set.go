// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/DanielOaks/girc-go/ircmatch"
)

var (
	ErrNickMissing      = errors.New("nick missing")
	ErrNicknameInUse    = errors.New("nickname in use")
	ErrNicknameMismatch = errors.New("nickname mismatch")
)

func ExpandUserHost(userhost string) (expanded string) {
	expanded = userhost
	// fill in missing wildcards for nicks
	//TODO(dan): this would fail with dan@lol, do we want to accommodate that?
	if !strings.Contains(expanded, "!") {
		expanded += "!*"
	}
	if !strings.Contains(expanded, "@") {
		expanded += "@*"
	}
	return
}

type ClientLookupSet struct {
	byNick map[string]*Client
}

func NewClientLookupSet() *ClientLookupSet {
	return &ClientLookupSet{
		byNick: make(map[string]*Client),
	}
}

func (clients *ClientLookupSet) Has(nick string) bool {
	casefoldedName, err := CasefoldName(nick)
	if err == nil {
		return false
	}
	_, exists := clients.byNick[casefoldedName]
	return exists
}

func (clients *ClientLookupSet) Get(nick string) *Client {
	casefoldedName, err := CasefoldName(nick)
	if err == nil {
		return clients.byNick[casefoldedName]
	}
	return nil
}

func (clients *ClientLookupSet) Add(client *Client) error {
	if !client.HasNick() {
		return ErrNickMissing
	}
	if clients.Get(client.nick) != nil {
		return ErrNicknameInUse
	}
	clients.byNick[client.nickCasefolded] = client
	return nil
}

func (clients *ClientLookupSet) Remove(client *Client) error {
	if !client.HasNick() {
		return ErrNickMissing
	}
	if clients.Get(client.nick) != client {
		return ErrNicknameMismatch
	}
	delete(clients.byNick, client.nickCasefolded)
	return nil
}

func (clients *ClientLookupSet) FindAll(userhost string) (set ClientSet) {
	set = make(ClientSet)

	userhost, err := Casefold(ExpandUserHost(userhost))
	if err != nil {
		return set
	}
	matcher := ircmatch.MakeMatch(userhost)

	for _, client := range clients.byNick {
		if matcher.Match(client.nickMaskCasefolded) {
			set.Add(client)
		}
	}

	return set
}

func (clients *ClientLookupSet) Find(userhost string) *Client {
	userhost, err := Casefold(ExpandUserHost(userhost))
	if err != nil {
		return nil
	}
	matcher := ircmatch.MakeMatch(userhost)

	for _, client := range clients.byNick {
		if matcher.Match(client.nickMaskCasefolded) {
			return client
		}
	}

	return nil
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
