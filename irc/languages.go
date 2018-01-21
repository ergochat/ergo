// Copyright (c) 2018 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"sync"
)

// LanguageManager manages our languages and provides translation abilities.
type LanguageManager struct {
	sync.RWMutex
	langMap map[string]map[string]string
}

// NewLanguageManager returns a new LanguageManager.
func NewLanguageManager() *LanguageManager {
	lm := LanguageManager{
		langMap: make(map[string]map[string]string),
	}

	//TODO(dan): load language files here

	return &lm
}

// Translate returns the given string, translated into the given language.
func (lm *LanguageManager) Translate(languages []string, originalString string) string {
	// not using any special languages
	if len(languages) == 0 {
		return originalString
	}

	lm.RLock()
	defer lm.RUnlock()

	for _, lang := range languages {
		langMap, exists := lm.langMap[lang]
		if !exists {
			continue
		}

		newString, exists := langMap[originalString]
		if !exists {
			continue
		}

		// found a valid translation!
		return newString
	}

	// didn't find any translation
	return originalString
}
