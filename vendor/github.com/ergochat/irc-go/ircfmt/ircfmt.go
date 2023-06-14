// written by Daniel Oaks <daniel@danieloaks.net>
// released under the ISC license

package ircfmt

import (
	"regexp"
	"strconv"
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

	metacharacters = (bold + colour + monospace + reverseColour + italic + strikethrough + underline + reset)
)

// ColorCode is a normalized representation of an IRC color code,
// as per this de facto specification: https://modern.ircdocs.horse/formatting.html#color
// The zero value of the type represents a default or unset color,
// whereas ColorCode{true, 0} represents the color white.
type ColorCode struct {
	IsSet bool
	Value uint8
}

// ParseColor converts a string representation of an IRC color code, e.g. "04",
// into a normalized ColorCode, e.g. ColorCode{true, 4}.
func ParseColor(str string) (color ColorCode) {
	// "99 - Default Foreground/Background - Not universally supported."
	// normalize 99 to ColorCode{} meaning "unset":
	if code, err := strconv.ParseUint(str, 10, 8); err == nil && code < 99 {
		color.IsSet = true
		color.Value = uint8(code)
	}
	return
}

// FormattedSubstring represents a section of an IRC message with associated
// formatting data.
type FormattedSubstring struct {
	Content         string
	ForegroundColor ColorCode
	BackgroundColor ColorCode
	Bold            bool
	Monospace       bool
	Strikethrough   bool
	Underline       bool
	Italic          bool
	ReverseColor    bool
}

// IsFormatted returns whether the section has any formatting flags switched on.
func (f *FormattedSubstring) IsFormatted() bool {
	// could rely on value receiver but if this is to be a public API,
	// let's make it a pointer receiver
	g := *f
	g.Content = ""
	return g != FormattedSubstring{}
}

var (
	// "If there are two ASCII digits available where a <COLOR> is allowed,
	// then two characters MUST always be read for it and displayed as described below."
	// we rely on greedy matching to implement this for both forms:
	// (\x03)00,01
	colorForeBackRe = regexp.MustCompile(`^([0-9]{1,2}),([0-9]{1,2})`)
	// (\x03)00
	colorForeRe = regexp.MustCompile(`^([0-9]{1,2})`)
)

// Split takes an IRC message (typically a PRIVMSG or NOTICE final parameter)
// containing IRC formatting control codes, and splits it into substrings with
// associated formatting information.
func Split(raw string) (result []FormattedSubstring) {
	var chunk FormattedSubstring
	for {
		// skip to the next metacharacter, or the end of the string
		if idx := strings.IndexAny(raw, metacharacters); idx != 0 {
			if idx == -1 {
				idx = len(raw)
			}
			chunk.Content = raw[:idx]
			if len(chunk.Content) != 0 {
				result = append(result, chunk)
			}
			raw = raw[idx:]
		}

		if len(raw) == 0 {
			return
		}

		// we're at a metacharacter. by default, all previous formatting carries over
		metacharacter := raw[0]
		raw = raw[1:]
		switch metacharacter {
		case bold[0]:
			chunk.Bold = !chunk.Bold
		case monospace[0]:
			chunk.Monospace = !chunk.Monospace
		case strikethrough[0]:
			chunk.Strikethrough = !chunk.Strikethrough
		case underline[0]:
			chunk.Underline = !chunk.Underline
		case italic[0]:
			chunk.Italic = !chunk.Italic
		case reverseColour[0]:
			chunk.ReverseColor = !chunk.ReverseColor
		case reset[0]:
			chunk = FormattedSubstring{}
		case colour[0]:
			// preferentially match the "\x0399,01" form, then "\x0399";
			// if neither of those matches, then it's a reset
			if matches := colorForeBackRe.FindStringSubmatch(raw); len(matches) != 0 {
				chunk.ForegroundColor = ParseColor(matches[1])
				chunk.BackgroundColor = ParseColor(matches[2])
				raw = raw[len(matches[0]):]
			} else if matches := colorForeRe.FindStringSubmatch(raw); len(matches) != 0 {
				chunk.ForegroundColor = ParseColor(matches[1])
				raw = raw[len(matches[0]):]
			} else {
				chunk.ForegroundColor = ColorCode{}
				chunk.BackgroundColor = ColorCode{}
			}
		default:
			// should be impossible, but just ignore it
		}
	}
}

var (
	// valtoescape replaces most of IRC characters with our escapes.
	valtoescape = strings.NewReplacer("$", "$$", colour, "$c", reverseColour, "$v", bold, "$b", italic, "$i", strikethrough, "$s", underline, "$u", monospace, "$m", reset, "$r")

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
		"gray":        "14",
		"light grey":  "15",
		"light gray":  "15",
		"default":     "99",
	}

	bracketedExpr = regexp.MustCompile(`^\[.*?\]`)
	colourDigits  = regexp.MustCompile(`^[0-9]{1,2}$`)
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

			if len(inRunes) < 1 || !isDigit(inRunes[0]) {
				out.WriteString("[]")
				continue
			}

			var foreBuffer, backBuffer string
			foreBuffer += string(inRunes[0])
			inRunes = inRunes[1:]
			if 0 < len(inRunes) && isDigit(inRunes[0]) {
				foreBuffer += string(inRunes[0])
				inRunes = inRunes[1:]
			}
			if 1 < len(inRunes) && inRunes[0] == ',' && isDigit(inRunes[1]) {
				backBuffer += string(inRunes[1])
				inRunes = inRunes[2:]
				if 0 < len(inRunes) && isDigit(inRunes[1]) {
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

func isDigit(r rune) bool {
	return '0' <= r && r <= '9' // don't use unicode.IsDigit, it includes non-ASCII numerals
}

// Strip takes a raw IRC string and removes it with all formatting codes removed
// IE, it turns this: "This is a \x02cool\x02, \x034red\x0f message!"
// into: "This is a cool, red message!"
func Strip(in string) string {
	splitChunks := Split(in)
	if len(splitChunks) == 0 {
		return ""
	} else if len(splitChunks) == 1 {
		return splitChunks[0].Content
	} else {
		var buf strings.Builder
		buf.Grow(len(in))
		for _, chunk := range splitChunks {
			buf.WriteString(chunk.Content)
		}
		return buf.String()
	}
}

// resolve "light blue" to "12", "12" to "12", "asdf" to "", etc.
func resolveToColourCode(str string) (result string) {
	str = strings.ToLower(strings.TrimSpace(str))
	if colourDigits.MatchString(str) {
		return str
	}
	return colourcodesTruncated[str]
}

// resolve "[light blue, black]" to ("13, "1")
func resolveToColourCodes(namedColors string) (foreground, background string) {
	// cut off the brackets
	namedColors = strings.TrimPrefix(namedColors, "[")
	namedColors = strings.TrimSuffix(namedColors, "]")

	var foregroundStr, backgroundStr string
	commaIdx := strings.IndexByte(namedColors, ',')
	if commaIdx != -1 {
		foregroundStr = namedColors[:commaIdx]
		backgroundStr = namedColors[commaIdx+1:]
	} else {
		foregroundStr = namedColors
	}

	return resolveToColourCode(foregroundStr), resolveToColourCode(backgroundStr)
}

// Unescape takes our escaped string and returns a raw IRC string.
//
// IE, it turns this: "This is a $bcool$b, $c[red]red$r message!"
// into this: "This is a \x02cool\x02, \x034red\x0f message!"
func Unescape(in string) string {
	var out strings.Builder

	remaining := in
	for len(remaining) != 0 {
		char := remaining[0]
		remaining = remaining[1:]

		if char != '$' || len(remaining) == 0 {
			// not an escape
			out.WriteByte(char)
			continue
		}

		// ingest the next character of the escape
		char = remaining[0]
		remaining = remaining[1:]

		if char == 'c' {
			out.WriteString(colour)

			namedColors := bracketedExpr.FindString(remaining)
			if namedColors == "" {
				// for a non-bracketed color code, output the following characters directly,
				// e.g., `$c1,8` will become `\x031,8`
				continue
			}
			// process bracketed color codes:
			remaining = remaining[len(namedColors):]
			followedByDigit := len(remaining) != 0 && ('0' <= remaining[0] && remaining[0] <= '9')

			foreground, background := resolveToColourCodes(namedColors)
			if foreground != "" {
				if len(foreground) == 1 && background == "" && followedByDigit {
					out.WriteByte('0')
				}
				out.WriteString(foreground)
				if background != "" {
					out.WriteByte(',')
					if len(background) == 1 && followedByDigit {
						out.WriteByte('0')
					}
					out.WriteString(background)
				}
			}
		} else {
			val, exists := escapetoval[rune(char)]
			if exists {
				out.WriteString(val)
			} else {
				// invalid escape, use the raw char
				out.WriteByte(char)
			}
		}
	}

	return out.String()
}
