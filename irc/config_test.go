// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package irc

import (
	"reflect"
	"testing"
)

func TestEnvironmentOverrides(t *testing.T) {
	var config Config
	config.Server.Compatibility.SendUnprefixedSasl = true
	config.History.Enabled = true
	defaultUserModes := "+i"
	config.Accounts.DefaultUserModes = &defaultUserModes
	config.Server.WebSockets.AllowedOrigins = []string{"https://www.ircv3.net"}
	config.Server.MOTD = "long.motd.txt" // overwrite this
	env := []string{
		`USER=shivaram`,        // unrelated var
		`ORAGONO_USER=oragono`, // this should be ignored as well
		`ERGO__NETWORK__NAME=example.com`,
		`ORAGONO__SERVER__COMPATIBILITY__FORCE_TRAILING=false`,
		`ORAGONO__SERVER__COERCE_IDENT="~user"`,
		`ERGO__SERVER__MOTD=short.motd.txt`,
		`ORAGONO__ACCOUNTS__NICK_RESERVATION__ENABLED=true`,
		`ERGO__ACCOUNTS__DEFAULT_USER_MODES="+iR"`,
		`ORAGONO__SERVER__IP_CLOAKING={"enabled": true, "enabled-for-always-on": true, "netname": "irc", "cidr-len-ipv4": 32, "cidr-len-ipv6": 64, "num-bits": 64}`,
	}
	for _, envPair := range env {
		_, _, err := mungeFromEnvironment(&config, envPair)
		if err != nil {
			t.Errorf("couldn't apply override `%s`: %v", envPair, err)
		}
	}

	if config.Network.Name != "example.com" {
		t.Errorf("unexpected value of network.name: %s", config.Network.Name)
	}
	if config.Server.CoerceIdent != "~user" {
		t.Errorf("unexpected value of coerce-ident: %s", config.Server.CoerceIdent)
	}
	if config.Server.MOTD != "short.motd.txt" {
		t.Errorf("unexpected value of motd: %s", config.Server.MOTD)
	}
	if !config.Accounts.NickReservation.Enabled {
		t.Errorf("did not set bool as expected")
	}
	if !config.Server.Compatibility.SendUnprefixedSasl {
		t.Errorf("overwrote unrelated field")
	}
	if !config.History.Enabled {
		t.Errorf("overwrote unrelated field")
	}
	if !reflect.DeepEqual(config.Server.WebSockets.AllowedOrigins, []string{"https://www.ircv3.net"}) {
		t.Errorf("overwrote unrelated field: %#v", config.Server.WebSockets.AllowedOrigins)
	}

	cloakConf := config.Server.Cloaks
	if !(cloakConf.Enabled == true && cloakConf.EnabledForAlwaysOn == true && cloakConf.Netname == "irc" && cloakConf.CidrLenIPv6 == 64) {
		t.Errorf("bad value of Cloaks: %#v", config.Server.Cloaks)
	}

	if *config.Server.Compatibility.ForceTrailing != false {
		t.Errorf("couldn't set unset ptr field to false")
	}

	if *config.Accounts.DefaultUserModes != "+iR" {
		t.Errorf("couldn't override pre-set ptr field")
	}
}

func TestEnvironmentOverrideErrors(t *testing.T) {
	var config Config
	config.Server.Compatibility.SendUnprefixedSasl = true
	config.History.Enabled = true

	invalidEnvs := []string{
		`ORAGONO__=asdf`,
		`ORAGONO__SERVER__=asdf`,
		`ORAGONO__SERVER____=asdf`,
		`ORAGONO__NONEXISTENT_KEY=1`,
		`ORAGONO__SERVER__NONEXISTENT_KEY=1`,
		// invalid yaml:
		`ORAGONO__SERVER__IP_CLOAKING__NETNAME="`,
		// invalid type:
		`ORAGONO__SERVER__IP_CLOAKING__NUM_BITS=asdf`,
		`ORAGONO__SERVER__STS=[]`,
		// index into non-struct:
		`ORAGONO__NETWORK__NAME__QUX=1`,
		// private field:
		`ORAGONO__SERVER__PASSWORDBYTES="asdf"`,
	}

	for _, env := range invalidEnvs {
		success, _, err := mungeFromEnvironment(&config, env)
		if err == nil || success {
			t.Errorf("accepted invalid env override `%s`", env)
		}
	}
}
