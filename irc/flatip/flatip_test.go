package flatip

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"testing"
	"time"
)

func easyParseIP(ipstr string) (result net.IP) {
	result = net.ParseIP(ipstr)
	if result == nil {
		panic(ipstr)
	}
	return
}

func easyParseFlat(ipstr string) (result IP) {
	x := easyParseIP(ipstr)
	return FromNetIP(x)
}

func easyParseIPNet(nipstr string) (result net.IPNet) {
	_, nip, err := net.ParseCIDR(nipstr)
	if err != nil {
		panic(err)
	}
	return *nip
}

func TestBasic(t *testing.T) {
	nip := easyParseIP("8.8.8.8")
	flatip := FromNetIP(nip)
	if flatip.String() != "8.8.8.8" {
		t.Errorf("conversions don't work")
	}
}

func TestLoopback(t *testing.T) {
	localhost_v4 := easyParseFlat("127.0.0.1")
	localhost_v4_again := easyParseFlat("127.2.3.4")
	google := easyParseFlat("8.8.8.8")
	loopback_v6 := easyParseFlat("::1")
	google_v6 := easyParseFlat("2607:f8b0:4006:801::2004")

	if !(localhost_v4.IsLoopback() && localhost_v4_again.IsLoopback() && loopback_v6.IsLoopback()) {
		t.Errorf("can't detect loopbacks")
	}

	if google_v6.IsLoopback() || google.IsLoopback() {
		t.Errorf("incorrectly detected loopbacks")
	}
}

func TestContains(t *testing.T) {
	nipnet := easyParseIPNet("8.8.0.0/16")
	flatipnet := FromNetIPNet(nipnet)
	nip := easyParseIP("8.8.8.8")
	flatip_ := FromNetIP(nip)
	if !flatipnet.Contains(flatip_) {
		t.Errorf("contains doesn't work")
	}
}

var testIPStrs = []string{
	"8.8.8.8",
	"127.0.0.1",
	"1.1.1.1",
	"128.127.65.64",
	"2001:0db8::1",
	"::1",
	"255.255.255.255",
}

func doMaskingTest(ip net.IP, t *testing.T) {
	flat := FromNetIP(ip)
	netLen := len(ip) * 8
	for i := 0; i < netLen; i++ {
		masked := flat.Mask(i, netLen)
		netMask := net.CIDRMask(i, netLen)
		netMasked := ip.Mask(netMask)
		if !bytes.Equal(masked[:], netMasked.To16()) {
			t.Errorf("Masking %s with %d/%d; expected %s, got %s", ip.String(), i, netLen, netMasked.String(), masked.String())
		}
	}
}

func assertEqual(found, expected interface{}) {
	if !reflect.DeepEqual(found, expected) {
		panic(fmt.Sprintf("expected %#v, found %#v", expected, found))
	}
}

func TestSize(t *testing.T) {
	_, net, err := ParseCIDR("8.8.8.8/24")
	if err != nil {
		panic(err)
	}
	ones, bits := net.Size()
	assertEqual(ones, 24)
	assertEqual(bits, 32)

	_, net, err = ParseCIDR("2001::0db8/64")
	if err != nil {
		panic(err)
	}
	ones, bits = net.Size()
	assertEqual(ones, 64)
	assertEqual(bits, 128)

	_, net, err = ParseCIDR("2001::0db8/96")
	if err != nil {
		panic(err)
	}
	ones, bits = net.Size()
	assertEqual(ones, 96)
	assertEqual(bits, 128)
}

func TestMasking(t *testing.T) {
	for _, ipstr := range testIPStrs {
		doMaskingTest(easyParseIP(ipstr), t)
	}
}

func TestMaskingFuzz(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	buf := make([]byte, 4)
	for i := 0; i < 10000; i++ {
		r.Read(buf)
		doMaskingTest(net.IP(buf), t)
	}

	buf = make([]byte, 16)
	for i := 0; i < 10000; i++ {
		r.Read(buf)
		doMaskingTest(net.IP(buf), t)
	}
}

func BenchmarkMasking(b *testing.B) {
	ip := easyParseIP("2001:0db8::42")
	flat := FromNetIP(ip)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		flat.Mask(64, 128)
	}
}

func BenchmarkMaskingLegacy(b *testing.B) {
	ip := easyParseIP("2001:0db8::42")
	mask := net.CIDRMask(64, 128)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ip.Mask(mask)
	}
}

func BenchmarkMaskingCached(b *testing.B) {
	i := easyParseIP("2001:0db8::42")
	flat := FromNetIP(i)
	mask := cidrMask(64, 128)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		flat.applyMask(mask)
	}
}

func BenchmarkMaskingConstruct(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cidrMask(69, 128)
	}
}

func BenchmarkContains(b *testing.B) {
	ip := easyParseIP("2001:0db8::42")
	flat := FromNetIP(ip)
	_, ipnet, err := net.ParseCIDR("2001:0db8::/64")
	if err != nil {
		panic(err)
	}
	flatnet := FromNetIPNet(*ipnet)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		flatnet.Contains(flat)
	}
}

func BenchmarkContainsLegacy(b *testing.B) {
	ip := easyParseIP("2001:0db8::42")
	_, ipnetptr, err := net.ParseCIDR("2001:0db8::/64")
	if err != nil {
		panic(err)
	}
	ipnet := *ipnetptr
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ipnet.Contains(ip)
	}
}
