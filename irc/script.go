// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package irc

import (
	"bufio"
	"io"
	"os/exec"
	"syscall"
	"time"
)

// general-purpose scripting API for oragono "plugins"
// invoke a command, send it a single newline-terminated string of bytes (typically JSON)
// get back another newline-terminated string of bytes (or an error)

// internal tupling of output and error for passing over a channel
type scriptResponse struct {
	output []byte
	err    error
}

func RunScript(command string, args []string, input []byte, timeout, killTimeout time.Duration) (output []byte, err error) {
	cmd := exec.Command(command, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}

	channel := make(chan scriptResponse, 1)
	err = cmd.Start()
	if err != nil {
		return
	}
	stdin.Write(input)
	stdin.Write([]byte{'\n'})

	// lots of potential race conditions here. we want to ensure that Wait()
	// will be called, and will return, on the other goroutine, no matter
	// where it is blocked. If it's blocked on ReadBytes(), we will kill it
	// (first with SIGTERM, then with SIGKILL) and ReadBytes will return
	// with EOF. If it's blocked on Wait(), then one of the kill signals
	// will succeed and unblock it.
	go processScriptOutput(cmd, stdout, channel)
	outputTimer := time.NewTimer(timeout)
	select {
	case response := <-channel:
		return response.output, response.err
	case <-outputTimer.C:
	}

	err = errTimedOut
	cmd.Process.Signal(syscall.SIGTERM)
	termTimer := time.NewTimer(killTimeout)
	select {
	case <-channel:
		return
	case <-termTimer.C:
	}

	cmd.Process.Kill()
	return
}

func processScriptOutput(cmd *exec.Cmd, stdout io.Reader, channel chan scriptResponse) {
	var response scriptResponse

	reader := bufio.NewReader(stdout)
	response.output, response.err = reader.ReadBytes('\n')

	// always call Wait() to ensure resource cleanup
	err := cmd.Wait()
	if err != nil {
		response.err = err
	}

	channel <- response
}
