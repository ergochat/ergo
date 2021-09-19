// Copyright (c) 2021 Shivaram Lingamneni
// released under the MIT license

package irc

import (
	"fmt"
	"runtime/debug"
)

// HandlePanic is a general-purpose panic handler for ad-hoc goroutines.
// Because of the semantics of `recover`, it must be called directly
// from the routine on whose call stack the panic would occur, with `defer`,
// e.g. `defer server.HandlePanic()`
func (server *Server) HandlePanic() {
	if r := recover(); r != nil {
		server.logger.Error("internal", fmt.Sprintf("Panic encountered: %v\n%s", r, debug.Stack()))
	}
}
