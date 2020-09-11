// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package irc

import (
	"errors"
	"net"
	"plugin"
)

const (
	IPPluginNotChecked  = 0
	IPPluginAccepted    = 1
	IPPluginBanned      = 2
	IPPluginRequireSASL = 3
)

// XXX the '=' makes this a "type alias" instead of a "type definition",
// allowing us to type-assert directly on the plugin.Symbol (since the plugin
// doesn't see our type definitions)
type IPChecker = func(ip net.IP) (result int, banMessage string, err error)

func LoadIPCheckPlugin(path string, args []string) (checker IPChecker, err error) {
	p, err := plugin.Open(path)
	if err != nil {
		return
	}
	initialize, err := p.Lookup("Initialize")
	if err != nil {
		return
	}
	check, err := p.Lookup("CheckIP")
	if err != nil {
		return
	}
	initializer, ok := initialize.(func([]string) error)
	if !ok {
		err = errors.New("ip check plugin exposes invalid signature for Initialize")
		return
	}
	checker, ok = check.(IPChecker)
	if !ok {
		err = errors.New("ip check plugin exposes invalid signature for CheckIP")
		return
	}
	err = initializer(args)
	return
}
