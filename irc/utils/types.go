// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package utils

type empty struct{}

type StringSet map[string]empty

func (s StringSet) Has(str string) bool {
	_, ok := s[str]
	return ok
}

func (s StringSet) Add(str string) {
	s[str] = empty{}
}

func (s StringSet) Remove(str string) {
	_, ok := s[str]
	if ok {
		delete(s, str)
	}
}

func (s StringSet) Size() int {
	return len(s)
}

func (s StringSet) Keys() (keys []string) {
	for key := range s {
		keys = append(keys, key)
	}

	return keys
}
