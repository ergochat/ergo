//go:build windows

// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package utils

import (
	"os"
	"syscall"
)

var (
	// ServerExitSignals are the signals the server will exit on.
	ServerExitSignals = []os.Signal{
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	}

	// no SIGUSR1 on windows
	ServerTracebackSignals []os.Signal
)
