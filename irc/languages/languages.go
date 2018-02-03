// Copyright (c) 2018 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package languages

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// LangData is the data contained in a language file.
type LangData struct {
	Name         string
	Code         string
	Contributors string
	Incomplete   bool
	Translations map[string]string
}

// Manager manages our languages and provides translation abilities.
type Manager struct {
	sync.RWMutex
	Info         map[string]LangData
	translations map[string]map[string]string
	defaultLang  string
}

// NewManager returns a new Manager.
func NewManager(defaultLang string, languageData map[string]LangData) *Manager {
	lm := Manager{
		Info:         make(map[string]LangData),
		translations: make(map[string]map[string]string),
		defaultLang:  defaultLang,
	}

	// make fake "en" info
	lm.Info["en"] = LangData{
		Code:         "en",
		Name:         "English",
		Contributors: "Oragono contributors and the IRC community",
	}

	// load language data
	for name, data := range languageData {
		lm.Info[name] = data

		// make sure we don't include empty translations
		lm.translations[name] = make(map[string]string)
		for key, value := range data.Translations {
			if strings.TrimSpace(value) == "" {
				continue
			}
			lm.translations[name][key] = value
		}
	}

	return &lm
}

// Default returns the default languages.
func (lm *Manager) Default() []string {
	lm.RLock()
	defer lm.RUnlock()

	if lm.defaultLang == "" {
		return []string{}
	}
	return []string{lm.defaultLang}
}

// Count returns how many languages we have.
func (lm *Manager) Count() int {
	lm.RLock()
	defer lm.RUnlock()

	return len(lm.Info)
}

// Translators returns the languages we have and the translators.
func (lm *Manager) Translators() []string {
	lm.RLock()
	defer lm.RUnlock()

	var tlist sort.StringSlice

	for _, info := range lm.Info {
		if info.Code == "en" {
			continue
		}
		tlist = append(tlist, fmt.Sprintf("%s (%s): %s", info.Name, info.Code, info.Contributors))
	}

	sort.Sort(tlist)
	return tlist
}

// Codes returns the proper language codes for the given casefolded language codes.
func (lm *Manager) Codes(codes []string) []string {
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
func (lm *Manager) Translate(languages []string, originalString string) string {
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
