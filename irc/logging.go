// Copyright (c) 2012-2014 Jeremy Latt
// released under the MIT license

package irc

import (
	"io"
	"log"
	"os"
)

type Logging struct {
	debug *log.Logger
	info  *log.Logger
	warn  *log.Logger
	error *log.Logger
}

var (
	levels = map[string]uint8{
		"debug": 4,
		"info":  3,
		"warn":  2,
		"error": 1,
	}
	devNull io.Writer
)

func init() {
	var err error
	devNull, err = os.Open(os.DevNull)
	if err != nil {
		log.Fatal(err)
	}
}

func NewLogger(on bool) *log.Logger {
	return log.New(output(on), "", log.LstdFlags)
}

func output(on bool) io.Writer {
	if on {
		return os.Stdout
	}
	return devNull
}

func (logging *Logging) SetLevel(level string) {
	logging.debug = NewLogger(levels[level] >= levels["debug"])
	logging.info = NewLogger(levels[level] >= levels["info"])
	logging.warn = NewLogger(levels[level] >= levels["warn"])
	logging.error = NewLogger(levels[level] >= levels["error"])
}

func NewLogging(level string) *Logging {
	logging := &Logging{}
	logging.SetLevel(level)
	return logging
}

var (
	// Log is the default logger.
	Log = NewLogging("warn")
)
