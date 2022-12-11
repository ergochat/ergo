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

func CopyMap[K comparable, V any](input map[K]V) (result map[K]V) {
	result = make(map[K]V, len(input))
	for key, value := range input {
		result[key] = value
	}
	return
}

// reverse the order of a slice in place
func ReverseSlice[T any](results []T) {
	for i, j := 0, len(results)-1; i < j; i, j = i+1, j-1 {
		results[i], results[j] = results[j], results[i]
	}
}

func SliceContains[T comparable](slice []T, elem T) (result bool) {
	for _, t := range slice {
		if elem == t {
			return true
		}
	}
	return false
}
