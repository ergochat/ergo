// Copyright (c) 2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package logger

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"time"

	"strings"

	"sync"
	"sync/atomic"

	colorable "github.com/mattn/go-colorable"
	"github.com/mgutz/ansi"
)

// Level represents the level to log messages at.
type Level int

const (
	// LogDebug represents debug messages.
	LogDebug Level = iota
	// LogInfo represents informational messages.
	LogInfo
	// LogWarning represents warnings.
	LogWarning
	// LogError represents errors.
	LogError
)

var (
	colorTimeGrey = ansi.ColorFunc("243")
	colorGrey     = ansi.ColorFunc("8")
	colorAlert    = ansi.ColorFunc("232+b:red")
	colorWarn     = ansi.ColorFunc("black:214")
	colorInfo     = ansi.ColorFunc("117")
	colorDebug    = ansi.ColorFunc("78")
	colorSection  = ansi.ColorFunc("229")
	separator     = colorGrey(":")

	colorableStdout = colorable.NewColorableStdout()
	colorableStderr = colorable.NewColorableStderr()
)

var (
	// LogLevelNames takes a config name and gives the real log level.
	LogLevelNames = map[string]Level{
		"debug":    LogDebug,
		"info":     LogInfo,
		"warn":     LogWarning,
		"warning":  LogWarning,
		"warnings": LogWarning,
		"error":    LogError,
		"errors":   LogError,
	}
	// LogLevelDisplayNames gives the display name to use for our log levels.
	LogLevelDisplayNames = map[Level]string{
		LogDebug:   "debug",
		LogInfo:    "info",
		LogWarning: "warning",
		LogError:   "error",
	}
)

// Manager is the main interface used to log debug/info/error messages.
type Manager struct {
	configMutex     sync.RWMutex
	loggers         []singleLogger
	stdoutWriteLock sync.Mutex // use one lock for both stdout and stderr
	fileWriteLock   sync.Mutex
	loggingRawIO    uint32
}

// LoggingConfig represents the configuration of a single logger.
type LoggingConfig struct {
	Method        string
	MethodStdout  bool
	MethodStderr  bool
	MethodFile    bool
	Filename      string
	TypeString    string   `yaml:"type"`
	Types         []string `yaml:"real-types"`
	ExcludedTypes []string `yaml:"real-excluded-types"`
	LevelString   string   `yaml:"level"`
	Level         Level    `yaml:"level-real"`
}

// NewManager returns a new log manager.
func NewManager(config []LoggingConfig) (*Manager, error) {
	var logger Manager

	if err := logger.ApplyConfig(config); err != nil {
		return nil, err
	}

	return &logger, nil
}

// ApplyConfig applies the given config to this logger (rehashes the config, in other words).
func (logger *Manager) ApplyConfig(config []LoggingConfig) error {
	logger.configMutex.Lock()
	defer logger.configMutex.Unlock()

	for _, logger := range logger.loggers {
		logger.Close()
	}

	logger.loggers = nil
	atomic.StoreUint32(&logger.loggingRawIO, 0)

	// for safety, this deep-copies all mutable data in `config`
	// XXX let's keep it that way
	var lastErr error
	for _, logConfig := range config {
		typeMap := make(map[string]bool)
		for _, name := range logConfig.Types {
			typeMap[name] = true
		}
		excludedTypeMap := make(map[string]bool)
		for _, name := range logConfig.ExcludedTypes {
			excludedTypeMap[name] = true
		}

		sLogger := singleLogger{
			MethodSTDOUT: logConfig.MethodStdout,
			MethodSTDERR: logConfig.MethodStderr,
			MethodFile: fileMethod{
				Enabled:  logConfig.MethodFile,
				Filename: logConfig.Filename,
			},
			Level:           logConfig.Level,
			Types:           typeMap,
			ExcludedTypes:   excludedTypeMap,
			stdoutWriteLock: &logger.stdoutWriteLock,
			fileWriteLock:   &logger.fileWriteLock,
		}
		ioEnabled := typeMap["userinput"] || typeMap["useroutput"] || (typeMap["*"] && !(excludedTypeMap["userinput"] && excludedTypeMap["useroutput"]))
		// raw I/O is only logged at level debug;
		if ioEnabled && logConfig.Level == LogDebug {
			atomic.StoreUint32(&logger.loggingRawIO, 1)
		}
		if sLogger.MethodFile.Enabled {
			file, err := os.OpenFile(sLogger.MethodFile.Filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
			if err != nil {
				lastErr = fmt.Errorf("Could not open log file %s [%s]", sLogger.MethodFile.Filename, err.Error())
			}
			writer := bufio.NewWriter(file)
			sLogger.MethodFile.File = file
			sLogger.MethodFile.Writer = writer
		}
		logger.loggers = append(logger.loggers, sLogger)
	}

	return lastErr
}

// IsLoggingRawIO returns true if raw user input and output is being logged.
func (logger *Manager) IsLoggingRawIO() bool {
	return atomic.LoadUint32(&logger.loggingRawIO) == 1
}

// Log logs the given message with the given details.
func (logger *Manager) Log(level Level, logType string, messageParts ...string) {
	logger.configMutex.RLock()
	defer logger.configMutex.RUnlock()

	for _, singleLogger := range logger.loggers {
		singleLogger.Log(level, logType, messageParts...)
	}
}

// Debug logs the given message as a debug message.
func (logger *Manager) Debug(logType string, messageParts ...string) {
	logger.Log(LogDebug, logType, messageParts...)
}

// Info logs the given message as an info message.
func (logger *Manager) Info(logType string, messageParts ...string) {
	logger.Log(LogInfo, logType, messageParts...)
}

// Warning logs the given message as a warning message.
func (logger *Manager) Warning(logType string, messageParts ...string) {
	logger.Log(LogWarning, logType, messageParts...)
}

// Error logs the given message as an error message.
func (logger *Manager) Error(logType string, messageParts ...string) {
	logger.Log(LogError, logType, messageParts...)
}

type fileMethod struct {
	Enabled  bool
	Filename string
	File     *os.File
	Writer   *bufio.Writer
}

// singleLogger represents a single logger instance.
type singleLogger struct {
	stdoutWriteLock *sync.Mutex
	fileWriteLock   *sync.Mutex
	MethodSTDOUT    bool
	MethodSTDERR    bool
	MethodFile      fileMethod
	Level           Level
	Types           map[string]bool
	ExcludedTypes   map[string]bool
}

func (logger *singleLogger) Close() error {
	if logger.MethodFile.Enabled {
		flushErr := logger.MethodFile.Writer.Flush()
		closeErr := logger.MethodFile.File.Close()
		if flushErr != nil {
			return flushErr
		}
		return closeErr
	}
	return nil
}

// Log logs the given message with the given details.
func (logger *singleLogger) Log(level Level, logType string, messageParts ...string) {
	// no logging enabled
	if !(logger.MethodSTDOUT || logger.MethodSTDERR || logger.MethodFile.Enabled) {
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

	levelDisplay := LogLevelDisplayNames[level]
	if level == LogError {
		levelDisplay = colorAlert(levelDisplay)
	} else if level == LogWarning {
		levelDisplay = colorWarn(levelDisplay)
	} else if level == LogInfo {
		levelDisplay = colorInfo(levelDisplay)
	} else if level == LogDebug {
		levelDisplay = colorDebug(levelDisplay)
	}

	var formattedBuf, rawBuf bytes.Buffer
	fmt.Fprintf(&formattedBuf, "%s %s %s %s %s %s ", colorTimeGrey(time.Now().UTC().Format("2006-01-02T15:04:05.000Z")), separator, levelDisplay, separator, colorSection(logType), separator)
	if logger.MethodFile.Enabled {
		fmt.Fprintf(&rawBuf, "%s : %s : %s : ", time.Now().UTC().Format("2006-01-02T15:04:05Z"), LogLevelDisplayNames[level], logType)
	}
	for i, p := range messageParts {
		formattedBuf.WriteString(p)
		if logger.MethodFile.Enabled {
			rawBuf.WriteString(p)
		}
		if i != len(messageParts)-1 {
			formattedBuf.WriteRune(' ')
			formattedBuf.WriteString(separator)
			formattedBuf.WriteRune(' ')
			if logger.MethodFile.Enabled {
				rawBuf.WriteString(" : ")
			}
		}
	}
	formattedBuf.WriteRune('\n')
	if logger.MethodFile.Enabled {
		rawBuf.WriteRune('\n')
	}

	// output
	if logger.MethodSTDOUT {
		logger.stdoutWriteLock.Lock()
		colorableStdout.Write(formattedBuf.Bytes())
		logger.stdoutWriteLock.Unlock()
	}
	if logger.MethodSTDERR {
		logger.stdoutWriteLock.Lock()
		colorableStderr.Write(formattedBuf.Bytes())
		logger.stdoutWriteLock.Unlock()
	}
	if logger.MethodFile.Enabled {
		logger.fileWriteLock.Lock()
		logger.MethodFile.Writer.Write(rawBuf.Bytes())
		logger.MethodFile.Writer.Flush()
		logger.fileWriteLock.Unlock()
	}
}
