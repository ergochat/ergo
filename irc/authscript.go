// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package irc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"syscall"
	"time"
)

// JSON-serializable input and output types for the script
type AuthScriptInput struct {
	AccountName string `json:"accountName,omitempty"`
	Passphrase  string `json:"passphrase,omitempty"`
	Certfp      string `json:"certfp,omitempty"`
	IP          string `json:"ip,omitempty"`
}

type AuthScriptOutput struct {
	AccountName string `json:"accountName"`
	Success     bool   `json:"success"`
	Error       string `json:"error"`
}

// internal tupling of output and error for passing over a channel
type authScriptResponse struct {
	output AuthScriptOutput
	err    error
}

func CheckAuthScript(config AuthScriptConfig, input AuthScriptInput) (output AuthScriptOutput, err error) {
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return
	}
	cmd := exec.Command(config.Command, config.Args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}

	channel := make(chan authScriptResponse, 1)
	err = cmd.Start()
	if err != nil {
		return
	}
	stdin.Write(inputBytes)
	stdin.Write([]byte{'\n'})

	// lots of potential race conditions here. we want to ensure that Wait()
	// will be called, and will return, on the other goroutine, no matter
	// where it is blocked. If it's blocked on ReadBytes(), we will kill it
	// (first with SIGTERM, then with SIGKILL) and ReadBytes will return
	// with EOF. If it's blocked on Wait(), then one of the kill signals
	// will succeed and unblock it.
	go processAuthScriptOutput(cmd, stdout, channel)
	outputTimer := time.NewTimer(config.Timeout)
	select {
	case response := <-channel:
		return response.output, response.err
	case <-outputTimer.C:
	}

	err = errTimedOut
	cmd.Process.Signal(syscall.SIGTERM)
	termTimer := time.NewTimer(config.Timeout)
	select {
	case <-channel:
		return
	case <-termTimer.C:
	}

	cmd.Process.Kill()
	return
}

func processAuthScriptOutput(cmd *exec.Cmd, stdout io.Reader, channel chan authScriptResponse) {
	var response authScriptResponse
	var out AuthScriptOutput

	reader := bufio.NewReader(stdout)
	outBytes, err := reader.ReadBytes('\n')
	if err == nil {
		err = json.Unmarshal(outBytes, &out)
		if err == nil {
			response.output = out
			if out.Error != "" {
				err = fmt.Errorf("Authentication process reported error: %s", out.Error)
			}
		}
	}
	response.err = err

	// always call Wait() to ensure resource cleanup
	err = cmd.Wait()
	if err != nil {
		response.err = err
	}

	channel <- response
}
