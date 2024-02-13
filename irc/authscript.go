// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package irc

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"

	"github.com/ergochat/ergo/irc/oauth2"
	"github.com/ergochat/ergo/irc/utils"
)

// JSON-serializable input and output types for the script
type AuthScriptInput struct {
	AccountName string   `json:"accountName,omitempty"`
	Passphrase  string   `json:"passphrase,omitempty"`
	Certfp      string   `json:"certfp,omitempty"`
	PeerCerts   []string `json:"peerCerts,omitempty"`
	peerCerts   []*x509.Certificate
	IP          string                     `json:"ip,omitempty"`
	OAuthBearer *oauth2.OAuthBearerOptions `json:"oauth2,omitempty"`
}

type AuthScriptOutput struct {
	AccountName string `json:"accountName"`
	Success     bool   `json:"success"`
	Error       string `json:"error"`
}

func CheckAuthScript(sem utils.Semaphore, config ScriptConfig, input AuthScriptInput) (output AuthScriptOutput, err error) {
	if sem != nil {
		sem.Acquire()
		defer sem.Release()
	}

	// PEM-encode the peer certificates before applying JSON
	if len(input.peerCerts) != 0 {
		input.PeerCerts = make([]string, len(input.peerCerts))
		for i, cert := range input.peerCerts {
			input.PeerCerts[i] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		}
	}

	inputBytes, err := json.Marshal(input)
	if err != nil {
		return
	}
	outBytes, err := RunScript(config.Command, config.Args, inputBytes, config.Timeout, config.KillTimeout)
	if err != nil {
		return
	}
	err = json.Unmarshal(outBytes, &output)
	if err != nil {
		return
	}

	if output.Error != "" {
		err = fmt.Errorf("Authentication process reported error: %s", output.Error)
	}
	return
}

type IPScriptResult uint

const (
	IPNotChecked  IPScriptResult = 0
	IPAccepted    IPScriptResult = 1
	IPBanned      IPScriptResult = 2
	IPRequireSASL IPScriptResult = 3
)

type IPScriptInput struct {
	IP string `json:"ip"`
}

type IPScriptOutput struct {
	Result     IPScriptResult `json:"result"`
	BanMessage string         `json:"banMessage"`
	// for caching: the network to which this result is applicable, and a TTL in seconds:
	CacheNet     string `json:"cacheNet"`
	CacheSeconds int    `json:"cacheSeconds"`
	Error        string `json:"error"`
}

func CheckIPBan(sem utils.Semaphore, config IPCheckScriptConfig, addr net.IP) (output IPScriptOutput, err error) {
	if sem != nil {
		sem.Acquire()
		defer sem.Release()
	}

	inputBytes, err := json.Marshal(IPScriptInput{IP: addr.String()})
	if err != nil {
		return
	}
	outBytes, err := RunScript(config.Command, config.Args, inputBytes, config.Timeout, config.KillTimeout)
	if err != nil {
		return
	}
	err = json.Unmarshal(outBytes, &output)
	if err != nil {
		return
	}

	if output.Error != "" {
		err = fmt.Errorf("IP ban process reported error: %s", output.Error)
	} else if !(IPAccepted <= output.Result && output.Result <= IPRequireSASL) {
		err = fmt.Errorf("Invalid result from IP checking script: %d", output.Result)
	}

	return
}
