// Copyright (c) 2018 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package languages

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

const (
	// for a language (e.g., `fi-FI`) to be supported
	// it must have a metadata file named, e.g., `fi-FI.lang.yaml`
	metadataFileSuffix = ".lang.yaml"
)

var (
	stringsFileSuffixes = []string{"-irc.lang.json", "-help.lang.json", "-nickserv.lang.json", "-hostserv.lang.json", "-chanserv.lang.json"}
)

// LangData is the data contained in a language file.
type LangData struct {
	Name         string
	Code         string
	Contributors string
	Incomplete   bool
}

// Manager manages our languages and provides translation abilities.
type Manager struct {
	Languages    map[string]LangData
	translations map[string]map[string]string
	defaultLang  string
}

// NewManager returns a new Manager.
func NewManager(enabled bool, path string, defaultLang string) (lm *Manager, err error) {
	lm = &Manager{
		Languages:    make(map[string]LangData),
		translations: make(map[string]map[string]string),
		defaultLang:  defaultLang,
	}

	// make fake "en" info
	lm.Languages["en"] = LangData{
		Code:         "en",
		Name:         "English",
		Contributors: "Oragono contributors and the IRC community",
	}

	if enabled {
		err = lm.loadData(path)
		if err == nil {
			// successful load, check that defaultLang is sane
			_, ok := lm.Languages[lm.defaultLang]
			if !ok {
				err = fmt.Errorf("Cannot find default language [%s]", lm.defaultLang)
			}
		}
	} else {
		lm.defaultLang = "en"
	}

	return
}

func (lm *Manager) loadData(path string) (err error) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return
	}

	// 1. for each language that has a ${langcode}.lang.yaml in the languages path
	// 2. load ${langcode}.lang.yaml
	// 3. load ${langcode}-irc.lang.json and friends as the translations
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		// glob up *.lang.yaml in the directory
		name := f.Name()
		if !strings.HasSuffix(name, metadataFileSuffix) {
			continue
		}
		prefix := strings.TrimSuffix(name, metadataFileSuffix)

		// load, e.g., `zh-CN.lang.yaml`
		var data []byte
		data, err = ioutil.ReadFile(filepath.Join(path, name))
		if err != nil {
			return
		}
		var langInfo LangData
		err = yaml.Unmarshal(data, &langInfo)
		if err != nil {
			return err
		}

		if langInfo.Code == "en" {
			return fmt.Errorf("Cannot have language file with code 'en' (this is the default language using strings inside the server code). If you're making an English variant, name it with a more specific code")
		}

		// check for duplicate languages
		_, exists := lm.Languages[strings.ToLower(langInfo.Code)]
		if exists {
			return fmt.Errorf("Language code [%s] defined twice", langInfo.Code)
		}

		// slurp up all translation files with `prefix` into a single translation map
		translations := make(map[string]string)
		for _, translationSuffix := range stringsFileSuffixes {
			stringsFilePath := filepath.Join(path, prefix+translationSuffix)
			data, err = ioutil.ReadFile(stringsFilePath)
			if err != nil {
				continue // skip missing paths
			}
			var tlList map[string]string
			err = json.Unmarshal(data, &tlList)
			if err != nil {
				return fmt.Errorf("invalid json for translation file %s: %s", stringsFilePath, err.Error())
			}

			for key, value := range tlList {
				// because of how crowdin works, this is how we skip untranslated lines
				if key == value || strings.TrimSpace(value) == "" {
					continue
				}
				translations[key] = value
			}
		}

		if len(translations) == 0 {
			// skip empty translations
			continue
		}

		// sanity check the language definition from the yaml file
		if langInfo.Code == "" || langInfo.Name == "" || langInfo.Contributors == "" {
			return fmt.Errorf("Code, name or contributors is empty in language file [%s]", name)
		}

		key := strings.ToLower(langInfo.Code)
		lm.Languages[key] = langInfo
		lm.translations[key] = translations
	}

	return nil
}

// Default returns the default languages.
func (lm *Manager) Default() []string {
	return []string{lm.defaultLang}
}

// Count returns how many languages we have.
func (lm *Manager) Count() int {
	return len(lm.Languages)
}

// Enabled returns whether translation is enabled.
func (lm *Manager) Enabled() bool {
	return len(lm.translations) != 0
}

// Translators returns the languages we have and the translators.
func (lm *Manager) Translators() []string {
	var tlist sort.StringSlice

	for _, info := range lm.Languages {
		if info.Code == "en" {
			continue
		}
		tlist = append(tlist, fmt.Sprintf("%s (%s): %s", info.Name, info.Code, info.Contributors))
	}

	tlist.Sort()
	return tlist
}

// Codes returns the proper language codes for the given casefolded language codes.
func (lm *Manager) Codes(codes []string) []string {
	var newCodes []string
	for _, code := range codes {
		info, exists := lm.Languages[code]
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

func (lm *Manager) CapValue() string {
	langCodes := make(sort.StringSlice, len(lm.Languages)+1)
	langCodes[0] = strconv.Itoa(len(lm.Languages))
	i := 1
	for _, info := range lm.Languages {
		codeToken := info.Code
		if info.Incomplete {
			codeToken = "~" + info.Code
		}
		langCodes[i] = codeToken
		i += 1
	}
	langCodes.Sort()
	return strings.Join(langCodes, ",")
}
