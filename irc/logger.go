// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"strings"

	"sync"

	colorable "github.com/mattn/go-colorable"
	"github.com/mgutz/ansi"
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
	logLevelDisplayNames = map[LogLevel]string{
		LogDebug: "debug",
		LogInfo:  "info",
		LogWarn:  "warning",
		LogError: "error",
	}
)

// Logger is the main interface used to log debug/info/error messages.
type Logger struct {
	loggers         []SingleLogger
	stderrWriteLock sync.Mutex
	DumpingRawInOut bool
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
			Level:           logConfig.Level,
			Types:           logConfig.Types,
			ExcludedTypes:   logConfig.ExcludedTypes,
			stderrWriteLock: &logger.stderrWriteLock,
		}
		if logConfig.Types["userinput"] || logConfig.Types["useroutput"] || (logConfig.Types["*"] && !(logConfig.ExcludedTypes["userinput"] && logConfig.ExcludedTypes["useroutput"])) {
			logger.DumpingRawInOut = true
		}
		if sLogger.MethodFile.Enabled {
			file, err := os.OpenFile(sLogger.MethodFile.Filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
			if err != nil {
				return nil, fmt.Errorf("Could not open log file %s [%s]", sLogger.MethodFile.Filename, err.Error())
			}
			writer := bufio.NewWriter(file)
			sLogger.MethodFile.File = file
			sLogger.MethodFile.Writer = writer
		}
		logger.loggers = append(logger.loggers, sLogger)
	}

	return &logger, nil
}

// Log logs the given message with the given details.
func (logger *Logger) Log(level LogLevel, logType string, messageParts ...string) {
	for _, singleLogger := range logger.loggers {
		singleLogger.Log(level, logType, messageParts...)
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
	stderrWriteLock *sync.Mutex
	MethodSTDERR    bool
	MethodFile      fileMethod
	Level           LogLevel
	Types           map[string]bool
	ExcludedTypes   map[string]bool
}

// Log logs the given message with the given details.
func (logger *SingleLogger) Log(level LogLevel, logType string, messageParts ...string) {
	// no logging enabled
	if !(logger.MethodSTDERR || logger.MethodFile.Enabled) {
		return
	}

	// ensure we're logging to the given level
	if level < logger.Level {
		return
	}

	// ensure we're capturing this logType
	logTypeCleaned := strings.ToLower(strings.TrimSpace(logType))
	capturing := (logger.Types["*"] || logger.Types[logTypeCleaned]) && !logger.ExcludedTypes["*"] && !logger.ExcludedTypes[logTypeCleaned]
	if !capturing {
		return
	}

	// assemble full line
	timeGrey := ansi.ColorFunc("243")
	grey := ansi.ColorFunc("8")
	alert := ansi.ColorFunc("232+b:red")
	warn := ansi.ColorFunc("black:214")
	info := ansi.ColorFunc("117")
	debug := ansi.ColorFunc("78")
	section := ansi.ColorFunc("229")

	levelDisplay := logLevelDisplayNames[level]
	if level == LogError {
		levelDisplay = alert(levelDisplay)
	} else if level == LogWarn {
		levelDisplay = warn(levelDisplay)
	} else if level == LogInfo {
		levelDisplay = info(levelDisplay)
	} else if level == LogDebug {
		levelDisplay = debug(levelDisplay)
	}

	sep := grey(":")
	fullStringFormatted := fmt.Sprintf("%s %s %s %s %s %s ", timeGrey(time.Now().UTC().Format("2006-01-02T15:04:05Z")), sep, levelDisplay, sep, section(logType), sep)
	fullStringRaw := fmt.Sprintf("%s : %s : %s : ", time.Now().UTC().Format("2006-01-02T15:04:05Z"), logLevelDisplayNames[level], section(logType))
	for i, p := range messageParts {
		fullStringFormatted += p
		fullStringRaw += p
		if i != len(messageParts)-1 {
			fullStringFormatted += " " + sep + " "
			fullStringRaw += " : "
		}
	}

	// output
	if logger.MethodSTDERR {
		logger.stderrWriteLock.Lock()
		fmt.Fprintln(colorable.NewColorableStderr(), fullStringFormatted)
		logger.stderrWriteLock.Unlock()
	}
	if logger.MethodFile.Enabled {
		logger.MethodFile.Writer.WriteString(fullStringRaw + "\n")
	}
}
