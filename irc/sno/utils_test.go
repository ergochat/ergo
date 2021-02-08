// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package sno

import (
	"fmt"
	"reflect"
	"testing"
)

func assertEqual(supplied, expected interface{}, t *testing.T) {
	if !reflect.DeepEqual(supplied, expected) {
		panic(fmt.Sprintf("expected %#v but got %#v", expected, supplied))
	}
}

func TestEvaluateSnomaskChanges(t *testing.T) {
	add, remove, newArg := EvaluateSnomaskChanges(true, "*", nil)
	assertEqual(add, Masks{'a', 'c', 'j', 'k', 'n', 'o', 'q', 't', 'u', 'v', 'x'}, t)
	assertEqual(len(remove), 0, t)
	assertEqual(newArg, "+acjknoqtuvx", t)

	add, remove, newArg = EvaluateSnomaskChanges(true, "*", Masks{'a', 'u'})
	assertEqual(add, Masks{'c', 'j', 'k', 'n', 'o', 'q', 't', 'v', 'x'}, t)
	assertEqual(len(remove), 0, t)
	assertEqual(newArg, "+cjknoqtvx", t)

	add, remove, newArg = EvaluateSnomaskChanges(true, "-a", Masks{'a', 'u'})
	assertEqual(len(add), 0, t)
	assertEqual(remove, Masks{'a'}, t)
	assertEqual(newArg, "-a", t)

	add, remove, newArg = EvaluateSnomaskChanges(true, "-*", Masks{'a', 'u'})
	assertEqual(len(add), 0, t)
	assertEqual(remove, Masks{'a', 'u'}, t)
	assertEqual(newArg, "-au", t)

	add, remove, newArg = EvaluateSnomaskChanges(true, "+c", Masks{'a', 'u'})
	assertEqual(add, Masks{'c'}, t)
	assertEqual(len(remove), 0, t)
	assertEqual(newArg, "+c", t)

	add, remove, newArg = EvaluateSnomaskChanges(false, "", Masks{'a', 'u'})
	assertEqual(len(add), 0, t)
	assertEqual(remove, Masks{'a', 'u'}, t)
	assertEqual(newArg, "", t)

	add, remove, newArg = EvaluateSnomaskChanges(false, "*", Masks{'a', 'u'})
	assertEqual(len(add), 0, t)
	assertEqual(remove, Masks{'a', 'u'}, t)
	assertEqual(newArg, "", t)
}
