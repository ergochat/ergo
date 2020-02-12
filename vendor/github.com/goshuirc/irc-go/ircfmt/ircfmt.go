// written by Daniel Oaks <daniel@danieloaks.net>
// released under the ISC license

package ircfmt

import (
	"strings"
)

const (
	// raw bytes and strings to do replacing with
	bold          string = "\x02"
	colour        string = "\x03"
	monospace     string = "\x11"
	reverseColour string = "\x16"
	italic        string = "\x1d"
	strikethrough string = "\x1e"
	underline     string = "\x1f"
	reset         string = "\x0f"

	runecolour        rune = '\x03'
	runebold          rune = '\x02'
	runemonospace     rune = '\x11'
	runereverseColour rune = '\x16'
	runeitalic        rune = '\x1d'
	runestrikethrough rune = '\x1e'
	runereset         rune = '\x0f'
	runeunderline     rune = '\x1f'

	// valid characters in a colour code character, for speed
	colours1 string = "0123456789"
)

var (
	// valtoescape replaces most of IRC characters with our escapes.
	valtoescape = strings.NewReplacer("$", "$$", colour, "$c", reverseColour, "$v", bold, "$b", italic, "$i", strikethrough, "$s", underline, "$u", monospace, "$m", reset, "$r")
	// valToStrip replaces most of the IRC characters with nothing
	valToStrip = strings.NewReplacer(colour, "$c", reverseColour, "", bold, "", italic, "", strikethrough, "", underline, "", monospace, "", reset, "")

	// escapetoval contains most of our escapes and how they map to real IRC characters.
	// intentionally skips colour, since that's handled elsewhere.
	escapetoval = map[rune]string{
		'$': "$",
		'b': bold,
		'i': italic,
		'v': reverseColour,
		's': strikethrough,
		'u': underline,
		'm': monospace,
		'r': reset,
	}

	// valid colour codes
	numtocolour = map[string]string{
		"99": "default",
		"15": "light grey",
		"14": "grey",
		"13": "pink",
		"12": "light blue",
		"11": "light cyan",
		"10": "cyan",
		"09": "light green",
		"08": "yellow",
		"07": "orange",
		"06": "magenta",
		"05": "brown",
		"04": "red",
		"03": "green",
		"02": "blue",
		"01": "black",
		"00": "white",
		"9":  "light green",
		"8":  "yellow",
		"7":  "orange",
		"6":  "magenta",
		"5":  "brown",
		"4":  "red",
		"3":  "green",
		"2":  "blue",
		"1":  "black",
		"0":  "white",
	}

	// full and truncated colour codes
	colourcodesFull = map[string]string{
		"white":       "00",
		"black":       "01",
		"blue":        "02",
		"green":       "03",
		"red":         "04",
		"brown":       "05",
		"magenta":     "06",
		"orange":      "07",
		"yellow":      "08",
		"light green": "09",
		"cyan":        "10",
		"light cyan":  "11",
		"light blue":  "12",
		"pink":        "13",
		"grey":        "14",
		"light grey":  "15",
		"default":     "99",
	}
	colourcodesTruncated = map[string]string{
		"white":       "0",
		"black":       "1",
		"blue":        "2",
		"green":       "3",
		"red":         "4",
		"brown":       "5",
		"magenta":     "6",
		"orange":      "7",
		"yellow":      "8",
		"light green": "9",
		"cyan":        "10",
		"light cyan":  "11",
		"light blue":  "12",
		"pink":        "13",
		"grey":        "14",
		"light grey":  "15",
		"default":     "99",
	}
)

// Escape takes a raw IRC string and returns it with our escapes.
//
// IE, it turns this: "This is a \x02cool\x02, \x034red\x0f message!"
// into: "This is a $bcool$b, $c[red]red$r message!"
func Escape(in string) string {
	// replace all our usual escapes
	in = valtoescape.Replace(in)

	inRunes := []rune(in)
	//var out string
	out := strings.Builder{}
	for 0 < len(inRunes) {
		if 1 < len(inRunes) && inRunes[0] == '$' && inRunes[1] == 'c' {
			// handle colours
			out.WriteString("$c")
			inRunes = inRunes[2:] // strip colour code chars

			if len(inRunes) < 1 || !strings.Contains(colours1, string(inRunes[0])) {
				out.WriteString("[]")
				continue
			}

			var foreBuffer, backBuffer string
			foreBuffer += string(inRunes[0])
			inRunes = inRunes[1:]
			if 0 < len(inRunes) && strings.Contains(colours1, string(inRunes[0])) {
				foreBuffer += string(inRunes[0])
				inRunes = inRunes[1:]
			}
			if 1 < len(inRunes) && inRunes[0] == ',' && strings.Contains(colours1, string(inRunes[1])) {
				backBuffer += string(inRunes[1])
				inRunes = inRunes[2:]
				if 0 < len(inRunes) && strings.Contains(colours1, string(inRunes[0])) {
					backBuffer += string(inRunes[0])
					inRunes = inRunes[1:]
				}
			}

			foreName, exists := numtocolour[foreBuffer]
			if !exists {
				foreName = foreBuffer
			}
			backName, exists := numtocolour[backBuffer]
			if !exists {
				backName = backBuffer
			}

			out.WriteRune('[')
			out.WriteString(foreName)
			if backName != "" {
				out.WriteRune(',')
				out.WriteString(backName)
			}
			out.WriteRune(']')

		} else {
			// special case for $$c
			if len(inRunes) > 2 && inRunes[0] == '$' && inRunes[1] == '$' && inRunes[2] == 'c' {
				out.WriteRune(inRunes[0])
				out.WriteRune(inRunes[1])
				out.WriteRune(inRunes[2])
				inRunes = inRunes[3:]
			} else {
				out.WriteRune(inRunes[0])
				inRunes = inRunes[1:]
			}
		}
	}

	return out.String()
}

// Strip takes a raw IRC string and removes it with all formatting codes removed
// IE, it turns this: "This is a \x02cool\x02, \x034red\x0f message!"
// into: "This is a cool, red message!"
func Strip(in string) string {
	out := strings.Builder{}
	runes := []rune(in)
	if out.Len() < len(runes) { // Reduce allocations where needed
		out.Grow(len(in) - out.Len())
	}
	for len(runes) > 0 {
		switch runes[0] {
		case runebold, runemonospace, runereverseColour, runeitalic, runestrikethrough, runeunderline, runereset:
			runes = runes[1:]
		case runecolour:
			runes = removeColour(runes)
		default:
			out.WriteRune(runes[0])
			runes = runes[1:]
		}
	}
	return out.String()
}

func removeNumber(runes []rune) []rune {
	if len(runes) > 0 && runes[0] >= '0' && runes[0] <= '9' {
		runes = runes[1:]
	}
	return runes
}

func removeColour(runes []rune) []rune {
	if runes[0] != runecolour {
		return runes
	}

	runes = runes[1:]
	runes = removeNumber(runes)
	runes = removeNumber(runes)

	if len(runes) > 1 && runes[0] == ',' && runes[1] >= '0' && runes[1] <= '9' {
		runes = runes[2:]
	} else {
		return runes // Nothing else because we dont have a comma
	}
	runes = removeNumber(runes)
	return runes
}

// Unescape takes our escaped string and returns a raw IRC string.
//
// IE, it turns this: "This is a $bcool$b, $c[red]red$r message!"
// into this: "This is a \x02cool\x02, \x034red\x0f message!"
func Unescape(in string) string {
	out := strings.Builder{}

	remaining := []rune(in)
	for 0 < len(remaining) {
		char := remaining[0]
		remaining = remaining[1:]

		if char == '$' && 0 < len(remaining) {
			char = remaining[0]
			remaining = remaining[1:]

			val, exists := escapetoval[char]
			if exists {
				out.WriteString(val)
			} else if char == 'c' {
				out.WriteString(colour)

				if len(remaining) < 2 || remaining[0] != '[' {
					continue
				}

				// get colour names
				var coloursBuffer string
				remaining = remaining[1:]
				for remaining[0] != ']' {
					coloursBuffer += string(remaining[0])
					remaining = remaining[1:]
				}
				remaining = remaining[1:] // strip final ']'

				colours := strings.Split(coloursBuffer, ",")
				var foreColour, backColour string
				foreColour = colours[0]
				if 1 < len(colours) {
					backColour = colours[1]
				}

				// decide whether we can use truncated colour codes
				canUseTruncated := len(remaining) < 1 || !strings.Contains(colours1, string(remaining[0]))

				// turn colour names into real codes
				var foreColourCode, backColourCode string
				var exists bool

				if backColour != "" || canUseTruncated {
					foreColourCode, exists = colourcodesTruncated[foreColour]
				} else {
					foreColourCode, exists = colourcodesFull[foreColour]
				}
				if exists {
					foreColour = foreColourCode
				}

				if backColour != "" {
					if canUseTruncated {
						backColourCode, exists = colourcodesTruncated[backColour]
					} else {
						backColourCode, exists = colourcodesFull[backColour]
					}
					if exists {
						backColour = backColourCode
					}
				}

				// output colour codes
				out.WriteString(foreColour)
				if backColour != "" {
					out.WriteRune(',')
					out.WriteString(backColour)
				}
			} else {
				// unknown char
				out.WriteRune(char)
			}
		} else {
			out.WriteRune(char)
		}
	}

	return out.String()
}
