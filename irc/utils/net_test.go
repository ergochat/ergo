// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2016 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package utils

import "net"
import "reflect"
import "testing"

func assertEqual(supplied, expected interface{}, t *testing.T) {
	if !reflect.DeepEqual(supplied, expected) {
		t.Errorf("expected %v but got %v", expected, supplied)
	}
}

// hostnames from https://github.com/DanielOaks/irc-parser-tests
var (
	goodHostnames = []string{
		"irc.example.com",
		"i.coolguy.net",
		"irc-srv.net.uk",
		"iRC.CooLguY.NeT",
		"gsf.ds342.co.uk",
		"324.net.uk",
		"xn--bcher-kva.ch",
		"pentos",
		"pentos.",
		"www.google.com.",
	}

	badHostnames = []string{
		"-lol-.net.uk",
		"-lol.net.uk",
		"_irc._sctp.lol.net.uk",
		"irc.l%l.net.uk",
		"irc..net.uk",
		".",
		"",
	}
)

func TestIsHostname(t *testing.T) {
	for _, name := range goodHostnames {
		if !IsHostname(name) {
			t.Error(
				"Expected to pass, but could not validate hostname",
				name,
			)
		}
	}

	for _, name := range badHostnames {
		if IsHostname(name) {
			t.Error(
				"Expected to fail, but successfully validated hostname",
				name,
			)
		}
	}
}

func TestIsServerName(t *testing.T) {
	if IsServerName("pentos") {
		t.Error("irc server names must contain a period")
	}
	if !IsServerName("darwin.network") {
		t.Error("failed to validate a perfectly good server name")
	}
}

func TestNormalizeToNet(t *testing.T) {
	a := net.ParseIP("8.8.8.8")
	b := net.ParseIP("8.8.4.4")
	if a == nil || b == nil {
		panic("something has gone very wrong")
	}

	aNetwork := NormalizeIPToNet(a)
	bNetwork := NormalizeIPToNet(b)

	assertEqual(aNetwork.Contains(a), true, t)
	assertEqual(bNetwork.Contains(b), true, t)
	assertEqual(aNetwork.Contains(b), false, t)
	assertEqual(bNetwork.Contains(a), false, t)

	c := net.ParseIP("2001:4860:4860::8888")
	d := net.ParseIP("2001:db8::1")
	if c == nil || d == nil {
		panic("something has gone very wrong")
	}

	cNetwork := NormalizeIPToNet(c)
	dNetwork := NormalizeIPToNet(d)

	assertEqual(cNetwork.Contains(c), true, t)
	assertEqual(dNetwork.Contains(d), true, t)
	assertEqual(dNetwork.Contains(c), false, t)
	assertEqual(dNetwork.Contains(a), false, t)
	assertEqual(cNetwork.Contains(b), false, t)
	assertEqual(aNetwork.Contains(c), false, t)
	assertEqual(bNetwork.Contains(c), false, t)

	assertEqual(NetToNormalizedString(aNetwork), "8.8.8.8", t)
	assertEqual(NetToNormalizedString(bNetwork), "8.8.4.4", t)
	assertEqual(NetToNormalizedString(cNetwork), "2001:4860:4860::8888", t)
	assertEqual(NetToNormalizedString(dNetwork), "2001:db8::1", t)
}

func TestNormalizedNetToString(t *testing.T) {
	_, network, err := net.ParseCIDR("8.8.0.0/16")
	if err != nil {
		panic(err)
	}
	assertEqual(NetToNormalizedString(*network), "8.8.0.0/16", t)

	normalized := NormalizeNet(*network)
	assertEqual(normalized.Contains(net.ParseIP("8.8.4.4")), true, t)
	assertEqual(normalized.Contains(net.ParseIP("1.1.1.1")), false, t)
	assertEqual(NetToNormalizedString(normalized), "8.8.0.0/16", t)

	_, network, err = net.ParseCIDR("8.8.4.4/32")
	if err != nil {
		panic(err)
	}
	assertEqual(NetToNormalizedString(*network), "8.8.4.4", t)

	normalized = NormalizeNet(*network)
	assertEqual(normalized.Contains(net.ParseIP("8.8.4.4")), true, t)
	assertEqual(normalized.Contains(net.ParseIP("8.8.8.8")), false, t)
	assertEqual(NetToNormalizedString(normalized), "8.8.4.4", t)
}

func TestNormalizedNet(t *testing.T) {
	_, network, err := net.ParseCIDR("::ffff:8.8.4.4/128")
	assertEqual(err, nil, t)
	assertEqual(NetToNormalizedString(*network), "8.8.4.4", t)

	normalizedNet := NormalizeIPToNet(net.ParseIP("8.8.4.4"))
	assertEqual(NetToNormalizedString(normalizedNet), "8.8.4.4", t)

	_, network, err = net.ParseCIDR("::ffff:8.8.0.0/112")
	assertEqual(err, nil, t)
	assertEqual(NetToNormalizedString(*network), "8.8.0.0/16", t)
	_, v4Network, err := net.ParseCIDR("8.8.0.0/16")
	assertEqual(err, nil, t)
	normalizedNet = NormalizeNet(*v4Network)
	assertEqual(NetToNormalizedString(normalizedNet), "8.8.0.0/16", t)
}

func TestNormalizedNetFromString(t *testing.T) {
	network, err := NormalizedNetFromString("8.8.4.4/16")
	assertEqual(err, nil, t)
	assertEqual(NetToNormalizedString(network), "8.8.0.0/16", t)
	assertEqual(network.Contains(net.ParseIP("8.8.8.8")), true, t)

	network, err = NormalizedNetFromString("2001:0db8::1")
	assertEqual(err, nil, t)
	assertEqual(NetToNormalizedString(network), "2001:db8::1", t)
	assertEqual(network.Contains(net.ParseIP("2001:0db8::1")), true, t)
}

func checkXFF(remoteAddr, forwardedHeader string, expectedStr string, t *testing.T) {
	whitelistCIDRs := []string{"10.0.0.0/8", "127.0.0.1/8"}
	var whitelist []net.IPNet
	for _, str := range whitelistCIDRs {
		_, wlNet, err := net.ParseCIDR(str)
		if err != nil {
			panic(err)
		}
		whitelist = append(whitelist, *wlNet)
	}

	expected := net.ParseIP(expectedStr)
	actual := HandleXForwardedFor(remoteAddr, forwardedHeader, whitelist)

	if !actual.Equal(expected) {
		t.Errorf("handling %s and %s, expected %s, got %s", remoteAddr, forwardedHeader, expected, actual)
	}
}

func TestXForwardedFor(t *testing.T) {
	checkXFF("8.8.4.4:9999", "", "8.8.4.4", t)
	// forged XFF header from untrustworthy external IP, should be ignored:
	checkXFF("8.8.4.4:9999", "1.1.1.1", "8.8.4.4", t)

	checkXFF("10.0.0.4:28432", "", "10.0.0.4", t)

	checkXFF("10.0.0.4:28432", "8.8.4.4", "8.8.4.4", t)
	checkXFF("10.0.0.4:28432", "10.0.0.3", "10.0.0.3", t)

	checkXFF("10.0.0.4:28432", "1.1.1.1, 8.8.4.4", "8.8.4.4", t)
	checkXFF("10.0.0.4:28432", "8.8.4.4, 1.1.1.1, 10.0.0.3", "1.1.1.1", t)
	checkXFF("10.0.0.4:28432", "10.0.0.1, 10.0.0.2, 10.0.0.3", "10.0.0.1", t)

	checkXFF("@", "8.8.4.4, 1.1.1.1, 10.0.0.3", "1.1.1.1", t)
}
