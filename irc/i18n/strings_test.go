//go:build i18n

package i18n

import "testing"

func validFoldTester(first, second string, equal bool, folder func(string) (string, error), t *testing.T) {
	firstFolded, err := folder(first)
	if err != nil {
		panic(err)
	}
	secondFolded, err := folder(second)
	if err != nil {
		panic(err)
	}
	foundEqual := firstFolded == secondFolded
	if foundEqual != equal {
		t.Errorf("%s and %s: expected equality %t, but got %t", first, second, equal, foundEqual)
	}
}

func TestFoldPermissive(t *testing.T) {
	tester := func(first, second string, equal bool) {
		validFoldTester(first, second, equal, foldPermissive, t)
	}
	tester("SHIVARAM", "shivaram", true)
	tester("shIvaram", "shivaraM", true)
	tester("shivaram", "DAN-", false)
	tester("dolph🐬n", "DOLPH🐬n", true)
	tester("dolph🐬n", "dolph💻n", false)
	tester("9FRONT", "9front", true)
}

func TestFoldPermissiveInvalid(t *testing.T) {
	_, err := foldPermissive("a\tb")
	if err == nil {
		t.Errorf("whitespace should be invalid in identifiers")
	}
	_, err = foldPermissive("a\x00b")
	if err == nil {
		t.Errorf("the null byte should be invalid in identifiers")
	}
	_, err = foldPermissive("a b")
	if err == nil {
		t.Errorf("space should be invalid in identifiers")
	}
}

func TestFoldPermissiveNormalization(t *testing.T) {
	tester := func(first, second string, equal bool) {
		validFoldTester(first, second, equal, foldPermissive, t)
	}

	// case folding should work on non-ASCII letters
	tester("Ω", "ω", true)         // Greek capital/small omega
	tester("Ñoño", "ñoño", true)   // Spanish precomposed tilde-n, upper vs lower
	tester("中文", "中文", true)       // CJK (no case distinction)
	tester("中文", "English", false) // different scripts, not equal

	// NFC-encoded input: "É" (U+00C9) and "é" (U+00E9) should fold equal
	// NFD normalization before case folding ensures composed chars are handled
	tester("\u00c9l\u00e8ve", "\u00e9l\u00e8ve", true) // Élève vs élève
}

func TestFoldASCII(t *testing.T) {
	tester := func(first, second string, equal bool) {
		validFoldTester(first, second, equal, foldASCII, t)
	}
	tester("shivaram", "SHIVARAM", true)
	tester("X|Y", "x|y", true)
	tester("a != b", "A != B", true)
}

func TestFoldASCIIInvalid(t *testing.T) {
	_, err := foldASCII("\x01")
	if err == nil {
		t.Errorf("control characters should be invalid in identifiers")
	}
	_, err = foldASCII("\x7F")
	if err == nil {
		t.Errorf("control characters should be invalid in identifiers")
	}
}

func TestFoldRFC1459(t *testing.T) {
	folder := func(str string) (string, error) {
		return foldRFC1459(str, false)
	}
	tester := func(first, second string, equal bool) {
		validFoldTester(first, second, equal, folder, t)
	}
	tester("shivaram", "SHIVARAM", true)
	tester("shivaram[a]", "shivaram{a}", true)
	tester("shivaram\\a]", "shivaram{a}", false)
	tester("shivaram\\a]", "shivaram|a}", true)
	tester("shivaram~a]", "shivaram^a}", true)
}

func TestFoldRFC1459Strict(t *testing.T) {
	folder := func(str string) (string, error) {
		return foldRFC1459(str, true)
	}
	tester := func(first, second string, equal bool) {
		validFoldTester(first, second, equal, folder, t)
	}
	tester("shivaram", "SHIVARAM", true)
	tester("shivaram[a]", "shivaram{a}", true)
	tester("shivaram\\a]", "shivaram{a}", false)
	tester("shivaram\\a]", "shivaram|a}", true)
	tester("shivaram~a]", "shivaram^a}", false)
}

func TestSkeleton(t *testing.T) {
	skeleton := func(str string) string {
		skel, err := Skeleton(str)
		if err != nil {
			t.Error(err)
		}
		return skel
	}

	if skeleton("warning") == skeleton("waming") {
		t.Errorf("Oragono shouldn't consider rn confusable with m")
	}

	if skeleton("Phi|ip") != "philip" {
		t.Errorf("but we still consider pipe confusable with l")
	}

	if skeleton("ｓｍｔ") != skeleton("smt") {
		t.Errorf("fullwidth characters should skeletonize to plain old ascii characters")
	}

	if skeleton("ＳＭＴ") != skeleton("smt") {
		t.Errorf("after skeletonizing, we should casefold")
	}

	if skeleton("smｔ") != skeleton("smt") {
		t.Errorf("our friend lover successfully tricked the skeleton algorithm!")
	}

	if skeleton("еvan") != "evan" {
		t.Errorf("we must protect against cyrillic homoglyph attacks")
	}

	if skeleton("еmily") != skeleton("emily") {
		t.Errorf("we must protect against cyrillic homoglyph attacks")
	}

	if skeleton("РОТАТО") != "potato" {
		t.Errorf("we must protect against cyrillic homoglyph attacks")
	}

	// should not raise an error:
	skeleton("けらんぐ")
}
