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

var (
	logLevelNames = map[string]LogLevel{
		"debug":    LogDebug,
		"info":     LogInfo,
		"warn":     LogWarn,
		"warning":  LogWarn,
		"warnings": LogWarn,
		"error":    LogError,
		"errors":   LogError,
	}
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
func NewLogger(config []LoggingConfig) (*Logger, error) {
	var logger Logger

	for _, logConfig := range config {
		sLogger := SingleLogger{
			MethodSTDERR: logConfig.Methods["stderr"],
			MethodFile: fileMethod{
				Enabled:  logConfig.Methods["file"],
				Filename: logConfig.Filename,
			},
			Level:         logConfig.Level,
			Types:         logConfig.Types,
			ExcludedTypes: logConfig.ExcludedTypes,
		}
		if sLogger.MethodFile.Enabled {
			file, err := os.OpenFile(sLogger.MethodFile.Filename, os.O_APPEND, 0666)
			if err != nil {
				return nil, fmt.Errorf("Could not open log file %s [%s]", sLogger.MethodFile.Filename, err.Error())
			}
			writer := bufio.NewWriter(file)
			sLogger.MethodFile.File = file
			sLogger.MethodFile.Writer = writer
		}
	}

	return &logger, nil
}

// Log logs the given message with the given details.
func (logger *Logger) Log(level LogLevel, logType, object, message string) {
	for _, singleLogger := range logger.loggers {
		singleLogger.Log(level, logType, object, message)
	}
}

type fileMethod struct {
	Enabled  bool
	Filename string
	File     *os.File
	Writer   *bufio.Writer
}

// SingleLogger represents a single logger instance.
type SingleLogger struct {
	MethodSTDERR  bool
	MethodFile    fileMethod
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
