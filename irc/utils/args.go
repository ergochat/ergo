// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package utils

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	IRCv3TimestampFormat = "2006-01-02T15:04:05.000Z"
)

var (
	ErrInvalidParams = errors.New("Invalid parameters")
)

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

func StringToBool(str string) (result bool, err error) {
	switch strings.ToLower(str) {
	case "on", "true", "t", "yes", "y", "enabled":
		result = true
	case "off", "false", "f", "no", "n", "disabled":
		result = false
	default:
		err = ErrInvalidParams
	}
	return
}

// Checks that a parameter can be passed as a non-trailing, and returns "*"
// if it can't. See #697.
func SafeErrorParam(param string) string {
	if param == "" || param[0] == ':' || strings.IndexByte(param, ' ') != -1 {
		return "*"
	}
	return param
}

type IncompatibleSchemaError struct {
	CurrentVersion  string
	RequiredVersion string
}

func (err *IncompatibleSchemaError) Error() string {
	return fmt.Sprintf("Database requires update. Expected schema v%s, got v%s", err.RequiredVersion, err.CurrentVersion)
}

func NanoToTimestamp(nanotime int64) string {
	return time.Unix(0, nanotime).UTC().Format(IRCv3TimestampFormat)
}
