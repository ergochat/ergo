// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package utils

type empty struct{}

type HashSet[T comparable] map[T]empty

func (s HashSet[T]) Has(elem T) bool {
	_, ok := s[elem]
	return ok
}

func (s HashSet[T]) Add(elem T) {
	s[elem] = empty{}
}

func (s HashSet[T]) Remove(elem T) {
	delete(s, elem)
}

func SetLiteral[T comparable](elems ...T) HashSet[T] {
	result := make(HashSet[T], len(elems))
	for _, elem := range elems {
		result.Add(elem)
	}
	return result
}

func CopyMap[K comparable, V any](input map[K]V) (result map[K]V) {
	result = make(map[K]V, len(input))
	for key, value := range input {
		result[key] = value
	}
	return
}

func SliceContains[T comparable](slice []T, elem T) (result bool) {
	for _, t := range slice {
		if elem == t {
			return true
		}
	}
	return false
}
