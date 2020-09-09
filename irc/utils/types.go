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
