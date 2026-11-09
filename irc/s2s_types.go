// Copyright (c) 2026 Ergo Developers
// released under the MIT license

package irc

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// ServerNode represents a server in the TS6 network graph.
type ServerNode struct {
	Name           string
	NameCasefolded string
	SID            string
	Description    string
	HopCount       int
	UplinkSID      string
	NextHop        *ServerLink
	IsLocal        bool
	IsDirect       bool
	Ctime          time.Time
}

// LinkConfig defines configuration for linking to a peer server.
type LinkConfig struct {
	Name            string `yaml:"name"`
	Hostname        string `yaml:"hostname"`
	Port            int    `yaml:"port"`
	SendPassword    string `yaml:"send-password"`
	ReceivePassword string `yaml:"receive-password"`
	TLS             bool   `yaml:"tls"`
	AutoConnect     bool   `yaml:"auto-connect"`
	SID             string `yaml:"sid"`
}

// UIDGenerator generates 9-character TS6 UIDs (3-character SID + 6-character sequence).
type UIDGenerator struct {
	sid     string
	counter atomic.Uint64
}

const uidAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// NewUIDGenerator creates a new TS6 UID generator for the given server SID.
func NewUIDGenerator(sid string) *UIDGenerator {
	return &UIDGenerator{sid: strings.ToUpper(sid)}
}

// Next returns the next 9-character TS6 UID.
func (g *UIDGenerator) Next() string {
	val := g.counter.Add(1)
	var buf [6]byte
	for i := 5; i >= 0; i-- {
		buf[i] = uidAlphabet[val%36]
		val /= 36
	}
	return g.sid + string(buf[:])
}

// IsValidSID checks if a string is a valid 3-character TS6 SID.
func IsValidSID(sid string) bool {
	if len(sid) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		c := sid[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	return true
}

// IsValidUID checks if a string is a valid 9-character TS6 UID.
func IsValidUID(uid string) bool {
	if len(uid) != 9 {
		return false
	}
	for i := 0; i < 9; i++ {
		c := uid[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	return true
}

// FormatErrorMsg formats an IRC ERROR message.
func FormatErrorMsg(reason string) string {
	return fmt.Sprintf("ERROR :%s\r\n", reason)
}
