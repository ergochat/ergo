// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package isupport

import (
	"fmt"
	"slices"
	"strings"
)

const (
	maxLastArgLength = 400

	/* Modern: "As the maximum number of message parameters to any reply is 15,
	the maximum number of RPL_ISUPPORT tokens that can be advertised is 13."
	<nickname> [up to 13 parameters] <human-readable trailing>
	*/
	maxParameters = 13
)

// List holds a list of ISUPPORT tokens
type List struct {
	Tokens      map[string]string
	CachedReply [][]string
}

// NewList returns a new List
func NewList() *List {
	var il List
	il.Initialize()
	return &il
}

func (il *List) Initialize() {
	il.Tokens = make(map[string]string)
	il.CachedReply = make([][]string, 0)
}

// Add adds an RPL_ISUPPORT token to our internal list
func (il *List) Add(name string, value string) {
	il.Tokens[name] = value
}

// AddNoValue adds an RPL_ISUPPORT token that does not have a value
func (il *List) AddNoValue(name string) {
	il.Tokens[name] = ""
}

// Contains returns whether the list already contains a token
func (il *List) Contains(name string) bool {
	_, ok := il.Tokens[name]
	return ok
}

// getTokenString gets the appropriate string for a token+value.
func getTokenString(name string, value string) string {
	if len(value) == 0 {
		return name
	}

	return fmt.Sprintf("%s=%s", name, value)
}

// GetDifference returns the difference between two token lists.
func (il *List) GetDifference(newil *List) [][]string {
	var outTokens []string

	// append removed tokens
	for name := range il.Tokens {
		_, exists := newil.Tokens[name]
		if exists {
			continue
		}

		token := fmt.Sprintf("-%s", name)

		outTokens = append(outTokens, token)
	}

	// append added tokens
	for name, value := range newil.Tokens {
		newval, exists := il.Tokens[name]
		if exists && value == newval {
			continue
		}

		token := getTokenString(name, value)

		outTokens = append(outTokens, token)
	}

	slices.Sort(outTokens)

	// create output list
	replies := make([][]string, 0)
	var length int     // Length of the current cache
	var cache []string // Token list cache

	for _, token := range outTokens {
		if len(token)+length <= maxLastArgLength {
			// account for the space separating tokens
			if len(cache) > 0 {
				length++
			}
			cache = append(cache, token)
			length += len(token)
		}

		if len(cache) == maxParameters || len(token)+length >= maxLastArgLength {
			replies = append(replies, cache)
			cache = make([]string, 0)
			length = 0
		}
	}

	if len(cache) > 0 {
		replies = append(replies, cache)
	}

	return replies
}

func validateToken(token string) error {
	if len(token) == 0 || token[0] == ':' || strings.Contains(token, " ") {
		return fmt.Errorf("bad isupport token (cannot be sent as IRC parameter): `%s`", token)
	}

	if strings.ContainsAny(token, "\n\r\x00") {
		return fmt.Errorf("bad isupport token (contains forbidden octets)")
	}

	// technically a token can be maxLastArgLength if it occurs alone,
	// but fail it just to be safe
	if len(token) >= maxLastArgLength {
		return fmt.Errorf("bad isupport token (too long): `%s`", token)
	}

	return nil
}

// RegenerateCachedReply regenerates the cached RPL_ISUPPORT reply
func (il *List) RegenerateCachedReply() (err error) {
	var tokens []string
	for name, value := range il.Tokens {
		token := getTokenString(name, value)
		if tokenErr := validateToken(token); tokenErr == nil {
			tokens = append(tokens, token)
		} else {
			err = tokenErr
		}
	}
	// make sure we get a sorted list of tokens, needed for tests and looks nice
	slices.Sort(tokens)

	var cache []string // Tokens in current line
	var length int     // Length of the current line

	for _, token := range tokens {
		// account for the space separating tokens
		if len(cache) == maxParameters || (len(token)+1)+length > maxLastArgLength {
			il.CachedReply = append(il.CachedReply, cache)
			cache = nil
			length = 0
		}

		if len(cache) > 0 {
			length++
		}
		length += len(token)
		cache = append(cache, token)
	}

	if len(cache) > 0 {
		il.CachedReply = append(il.CachedReply, cache)
	}

	return
}
