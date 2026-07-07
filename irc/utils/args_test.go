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

func TestIsValidBatchTag(t *testing.T) {
	assertEqual(IsValidBatchTag("-"), true, t)
	assertEqual(IsValidBatchTag("1"), true, t)
	assertEqual(IsValidBatchTag("x"), true, t)
	assertEqual(IsValidBatchTag("9P5fxSwIXviY1YHHuejhaQ"), true, t)
	assertEqual(IsValidBatchTag("0123456789-abcdef"), true, t)

	assertEqual(IsValidBatchTag(""), false, t)
	assertEqual(IsValidBatchTag("_"), false, t)
	assertEqual(IsValidBatchTag("qt-KrJ5H6bNsaLr_mDE4QQ"), false, t)
}
