// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"bufio"
	"fmt"
	"os"
	"time"
)

// LogLevel represents the level to log messages at.
type LogLevel int

const (
	// LogDebug represents debug messages.
	LogDebug LogLevel = iota
	// LogInfo represents informational messages.
	LogInfo
	// LogWarn represents warnings.
	LogWarn
	// LogError represents errors.
	LogError
)

// ClientLogger is a logger dedicated to a single client. This is a convenience class that
// automagically adds the client nick to logged messages.
type ClientLogger struct {
	client *Client
}

// NewClientLogger returns a new ClientLogger.
func NewClientLogger(client *Client) ClientLogger {
	logger := ClientLogger{
		client: client,
	}
	return logger
}

// Log logs the given message with the given details.
func (logger *ClientLogger) Log(level LogLevel, logType, object, message string) {
	object = fmt.Sprintf("%s : %s", logger.client.nick, object)
	logger.client.server.logger.Log(level, logType, object, message)
}

// Logger is the main interface used to log debug/info/error messages.
type Logger struct {
	loggers []SingleLogger
}

// NewLogger returns a new Logger.
func NewLogger(config LogConfig) (*Logger, error) {
	return nil, fmt.Errorf("Not implemented")
}

// Log logs the given message with the given details.
func (logger *Logger) Log(level LogLevel, logType, object, message string) {
	for _, singleLogger := range logger.loggers {
		singleLogger.Log(level, logType, object, message)
	}
}

// SingleLogger represents a single logger instance.
type SingleLogger struct {
	MethodSTDERR bool
	MethodFile   struct {
		Enabled  bool
		Filename string
		File     os.File
		Writer   bufio.Writer
	}
	Level         LogLevel
	Types         map[string]bool
	ExcludedTypes map[string]bool
}

// Log logs the given message with the given details.
func (logger *SingleLogger) Log(level LogLevel, logType, object, message string) {
	// no logging enabled
	if !(logger.MethodSTDERR || logger.MethodFile.Enabled) {
		return
	}

	// ensure we're logging to the given level
	if level < logger.Level {
		return
	}

	// ensure we're capturing this logType
	capturing := (logger.Types["*"] || logger.Types[logType]) && !logger.ExcludedTypes["*"] && !logger.ExcludedTypes[logType]
	if !capturing {
		return
	}

	// assemble full line
	fullString := fmt.Sprintf("%s : %s : %s : %s", time.Now().UTC().Format("2006-01-02T15:04:05.999Z"), logType, object, message)

	// output
	if logger.MethodSTDERR {
		fmt.Fprintln(os.Stderr, fullString)
	}
	if logger.MethodFile.Enabled {
		logger.MethodFile.Writer.WriteString(fullString + "\n")
	}
}
