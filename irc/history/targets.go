// Copyright (c) 2021 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package history

import (
	"slices"
	"sort"
	"time"
)

type TargetListing struct {
	CfName string
	Time   time.Time
}

// Merge `base`, a paging window of targets, with `extras` (the target entries
// for all joined channels).
func MergeTargets(base []TargetListing, extra []TargetListing, start, end time.Time, limit int) (results []TargetListing) {
	if len(extra) == 0 {
		return base
	}
	SortCorrespondents(extra)

	start, end, ascending := MinMaxAsc(start, end, time.Time{})
	predicate := func(t time.Time) bool {
		return (start.IsZero() || start.Before(t)) && (end.IsZero() || end.After(t))
	}

	prealloc := len(base) + len(extra)
	if limit < prealloc {
		prealloc = limit
	}
	results = make([]TargetListing, 0, prealloc)

	if !ascending {
		slices.Reverse(base)
		slices.Reverse(extra)
	}

	for len(results) < limit {
		if len(extra) != 0 {
			if !predicate(extra[0].Time) {
				extra = extra[1:]
				continue
			}
			if len(base) != 0 {
				if base[0].Time.Before(extra[0].Time) == ascending {
					results = append(results, base[0])
					base = base[1:]
				} else {
					results = append(results, extra[0])
					extra = extra[1:]
				}
			} else {
				results = append(results, extra[0])
				extra = extra[1:]
			}
		} else if len(base) != 0 {
			results = append(results, base[0])
			base = base[1:]
		} else {
			break
		}
	}

	if !ascending {
		slices.Reverse(results)
	}
	return
}

func SortCorrespondents(list []TargetListing) {
	sort.Slice(list, func(i, j int) bool {
		return list[i].Time.Before(list[j].Time)
	})
}
