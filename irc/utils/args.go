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
	CurrentVersion  int
	RequiredVersion int
}

func (err *IncompatibleSchemaError) Error() string {
	return fmt.Sprintf("Database requires update. Expected schema v%d, got v%d", err.RequiredVersion, err.CurrentVersion)
}

func NanoToTimestamp(nanotime int64) string {
	return time.Unix(0, nanotime).UTC().Format(IRCv3TimestampFormat)
}

func BoolDefaultTrue(value *bool) bool {
	if value != nil {
		return *value
	}
	return true
}
