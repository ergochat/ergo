// Copyright (c) 2018 Shivaram Lingamneni
// released under the MIT license

package modes

import (
	"reflect"
	"testing"
)

func TestSetMode(t *testing.T) {
	set := NewModeSet()

	if applied := set.SetMode(Invisible, false); applied != false {
		t.Errorf("all modes should be false by default")
	}

	if applied := set.SetMode(Invisible, true); applied != true {
		t.Errorf("initial SetMode call should return true")
	}

	set.SetMode(Operator, true)

	if applied := set.SetMode(Invisible, true); applied != false {
		t.Errorf("redundant SetMode call should return false")
	}

	expected1 := []Mode{Invisible, Operator}
	expected2 := []Mode{Operator, Invisible}
	if allModes := set.AllModes(); !(reflect.DeepEqual(allModes, expected1) || reflect.DeepEqual(allModes, expected2)) {
		t.Errorf("unexpected AllModes value: %v", allModes)
	}

	if modeString := set.String(); !(modeString == "io" || modeString == "oi") {
		t.Errorf("unexpected modestring: %s", modeString)
	}
}
