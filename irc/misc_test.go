// Copyright (c) 2019 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"testing"
	"time"
)

func TestZncTimestampParser(t *testing.T) {
	assertEqual(zncWireTimeToTime("1558338348.988"), time.Unix(1558338348, 988000000).UTC(), t)
	assertEqual(zncWireTimeToTime("1558338348.9"), time.Unix(1558338348, 900000000).UTC(), t)
	assertEqual(zncWireTimeToTime("1558338348"), time.Unix(1558338348, 0).UTC(), t)
	assertEqual(zncWireTimeToTime("1558338348.99999999999999999999999999999"), time.Unix(1558338348, 999999999).UTC(), t)
	assertEqual(zncWireTimeToTime("1558338348.999999999111111111"), time.Unix(1558338348, 999999999).UTC(), t)
	assertEqual(zncWireTimeToTime("1558338348.999999991111111111"), time.Unix(1558338348, 999999991).UTC(), t)
	assertEqual(zncWireTimeToTime(".988"), time.Unix(0, 988000000).UTC(), t)
	assertEqual(zncWireTimeToTime("0"), time.Unix(0, 0).UTC(), t)
	assertEqual(zncWireTimeToTime("garbage"), time.Unix(0, 0).UTC(), t)
	assertEqual(zncWireTimeToTime(""), time.Unix(0, 0).UTC(), t)
}
