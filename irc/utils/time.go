package utils

import (
	"time"
)

// ReadMarkerLessThanOrEqual compares times from the standpoint of
// draft/read-marker (the presentation format of which truncates the time
// to the millisecond). In future we might want to consider proactively rounding,
// instead of truncating, the time, but this has complex implications.
func ReadMarkerLessThanOrEqual(t1, t2 time.Time) bool {
	t1 = t1.Truncate(time.Millisecond)
	t2 = t2.Truncate(time.Millisecond)
	return t1.Before(t2) || t1.Equal(t2)
}
