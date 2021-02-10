// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package sno

import (
	"strings"
)

func IsValidMask(r rune) bool {
	for _, m := range ValidMasks {
		if m == Mask(r) {
			return true
		}
	}
	return false
}

func (masks Masks) String() string {
	var buf strings.Builder
	buf.Grow(len(masks))
	for _, m := range masks {
		buf.WriteRune(rune(m))
	}
	return buf.String()
}

func (masks Masks) Contains(mask Mask) bool {
	for _, m := range masks {
		if mask == m {
			return true
		}
	}
	return false
}

// Evaluate changes to snomasks made with MODE. There are several cases:
// adding snomasks with `/mode +s a` or `/mode +s +a`, removing them with `/mode +s -a`,
// adding all with `/mode +s *` or `/mode +s +*`, removing all with `/mode +s -*` or `/mode -s`
func EvaluateSnomaskChanges(add bool, arg string, currentMasks Masks) (addMasks, removeMasks Masks, newArg string) {
	if add {
		if len(arg) == 0 {
			return
		}
		add := true
		switch arg[0] {
		case '+':
			arg = arg[1:]
		case '-':
			add = false
			arg = arg[1:]
		default:
			// add
		}
		if strings.IndexByte(arg, '*') != -1 {
			if add {
				for _, mask := range ValidMasks {
					if !currentMasks.Contains(mask) {
						addMasks = append(addMasks, mask)
					}
				}
			} else {
				removeMasks = currentMasks
			}
		} else {
			for _, r := range arg {
				if IsValidMask(r) {
					m := Mask(r)
					if add && !currentMasks.Contains(m) {
						addMasks = append(addMasks, m)
					} else if !add && currentMasks.Contains(m) {
						removeMasks = append(removeMasks, m)
					}
				}
			}
		}
		if len(addMasks) != 0 {
			newArg = "+" + addMasks.String()
		} else if len(removeMasks) != 0 {
			newArg = "-" + removeMasks.String()
		}
	} else {
		removeMasks = currentMasks
		newArg = ""
	}
	return
}
