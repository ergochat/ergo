// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import (
	"testing"
	"time"
)

func easyParse(timestamp string) time.Time {
	result, err := time.Parse("2006-01-02 15:04:05Z", timestamp)
	if err != nil {
		panic(err)
	}
	return result
}

func TestConfirmation(t *testing.T) {
	set := make(map[string]struct{})

	set[ConfirmationCode("#darwin", easyParse("2006-01-01 00:00:00Z"))] = struct{}{}
	set[ConfirmationCode("#darwin", easyParse("2006-01-02 00:00:00Z"))] = struct{}{}
	set[ConfirmationCode("#xelpers", easyParse("2006-01-01 00:00:00Z"))] = struct{}{}
	set[ConfirmationCode("#xelpers", easyParse("2006-01-02 00:00:00Z"))] = struct{}{}

	if len(set) != 4 {
		t.Error("confirmation codes are not unique")
	}

	for code := range set {
		if len(code) <= 2 || len(code) >= 8 {
			t.Errorf("bad code: %s", code)
		}
	}
}
