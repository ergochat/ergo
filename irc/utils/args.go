// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package utils

import "strings"

// ExtractParam extracts a parameter from the given string, returning the param and the rest of the string.
func ExtractParam(line string) (string, string) {
	rawParams := strings.SplitN(strings.TrimSpace(line), " ", 2)
	param0 := rawParams[0]
	var param1 string
	if 1 < len(rawParams) {
		param1 = strings.TrimSpace(rawParams[1])
	}
	return param0, param1
}

// ArgsToStrings takes the arguments and splits them into a series of strings,
// each argument separated by delim and each string bounded by maxLength.
func ArgsToStrings(maxLength int, arguments []string, delim string) []string {
	var messages []string

	var buffer string
	for {
		if len(arguments) < 1 {
			break
		}

		if len(buffer) > 0 && maxLength < len(buffer)+len(delim)+len(arguments[0]) {
			messages = append(messages, buffer)
			buffer = ""
			continue
		}

		if len(buffer) > 1 {
			buffer += delim
		}
		buffer += arguments[0]
		arguments = arguments[1:]
	}

	if len(buffer) > 0 {
		messages = append(messages, buffer)
	}

	return messages
}
