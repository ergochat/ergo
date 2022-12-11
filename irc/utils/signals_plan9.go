//go:build plan9
// +build plan9

// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package utils

import (
	"os"
	"syscall"
)

var (
	// ServerExitSignals are the signals the server will exit on.
	// (no SIGQUIT on plan9)
	ServerExitSignals = []os.Signal{
		syscall.SIGINT,
		syscall.SIGTERM,
	}

	// no SIGUSR1 on plan9
	ServerTracebackSignals []os.Signal
)
