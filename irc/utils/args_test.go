// Copyright (c) 2019 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import "testing"

func TestStringToBool(t *testing.T) {
	val, err := StringToBool("on")
	assertEqual(val, true, t)
	assertEqual(err, nil, t)

	val, err = StringToBool("n")
	assertEqual(val, false, t)
	assertEqual(err, nil, t)

	val, err = StringToBool("OFF")
	assertEqual(val, false, t)
	assertEqual(err, nil, t)

	val, err = StringToBool("default")
	assertEqual(err, ErrInvalidParams, t)
}

func TestSafeErrorParam(t *testing.T) {
	assertEqual(SafeErrorParam("hi"), "hi", t)
	assertEqual(SafeErrorParam("#hi"), "#hi", t)
	assertEqual(SafeErrorParam("#hi there"), "*", t)
	assertEqual(SafeErrorParam(":"), "*", t)
	assertEqual(SafeErrorParam("#hi:there"), "#hi:there", t)
	assertEqual(SafeErrorParam(""), "*", t)
}
