// Copyright (c) 2018 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"strings"
	"sync"
)

// LanguageManager manages our languages and provides translation abilities.
type LanguageManager struct {
	sync.RWMutex
	Info         map[string]LangData
	translations map[string]map[string]string
}

// NewLanguageManager returns a new LanguageManager.
func NewLanguageManager(languageData map[string]LangData) *LanguageManager {
	lm := LanguageManager{
		Info:         make(map[string]LangData),
		translations: make(map[string]map[string]string),
	}

	// make fake "en" info
	lm.Info["en"] = LangData{
		Code:        "en",
		Name:        "English",
		Maintainers: "Oragono contributors and the IRC community",
	}

	// load language data
	for name, data := range languageData {
		lm.Info[name] = data
		lm.translations[name] = data.Translations
	}

	return &lm
}

// Count returns how many languages we have.
func (lm *LanguageManager) Count() int {
	lm.RLock()
	defer lm.RUnlock()

	return len(lm.Info)
}

// Codes returns the proper language codes for the given casefolded language codes.
func (lm *LanguageManager) Codes(codes []string) []string {
	lm.RLock()
	defer lm.RUnlock()

	var newCodes []string
	for _, code := range codes {
		info, exists := lm.Info[code]
		if exists {
			newCodes = append(newCodes, info.Code)
		}
	}

	if len(newCodes) == 0 {
		newCodes = []string{"en"}
	}

	return newCodes
}

// Translate returns the given string, translated into the given language.
func (lm *LanguageManager) Translate(languages []string, originalString string) string {
	// not using any special languages
	if len(languages) == 0 || languages[0] == "en" || len(lm.translations) == 0 {
		return originalString
	}

	lm.RLock()
	defer lm.RUnlock()

	for _, lang := range languages {
		lang = strings.ToLower(lang)
		if lang == "en" {
			return originalString
		}

		translations, exists := lm.translations[lang]
		if !exists {
			continue
		}

		newString, exists := translations[originalString]
		if !exists {
			continue
		}

		// found a valid translation!
		return newString
	}

	// didn't find any translation
	return originalString
}
