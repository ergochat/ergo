// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"io"
	"math/rand"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/oragono/oragono/irc/utils"
)

// mockConn is a fake net.Conn / io.Reader that yields len(counts) lines,
// each consisting of counts[i] 'a' characters and a terminating '\n'
type mockConn struct {
	counts []int
}

func min(i, j int) (m int) {
	if i < j {
		return i
	} else {
		return j
	}
}

func (c *mockConn) Read(b []byte) (n int, err error) {
	for len(b) > 0 {
		if len(c.counts) == 0 {
			return n, io.EOF
		}
		if c.counts[0] == 0 {
			b[0] = '\n'
			c.counts = c.counts[1:]
			b = b[1:]
			n += 1
			continue
		}
		size := min(c.counts[0], len(b))
		for i := 0; i < size; i++ {
			b[i] = 'a'
		}
		c.counts[0] -= size
		b = b[size:]
		n += size
	}
	return n, nil
}

func (c *mockConn) Write(b []byte) (n int, err error) {
	return
}

func (c *mockConn) Close() error {
	c.counts = nil
	return nil
}

func (c *mockConn) LocalAddr() net.Addr {
	return nil
}

func (c *mockConn) RemoteAddr() net.Addr {
	return nil
}

func (c *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func newMockConn(counts []int) *utils.WrappedConn {
	cpCounts := make([]int, len(counts))
	copy(cpCounts, counts)
	c := &mockConn{
		counts: cpCounts,
	}
	return &utils.WrappedConn{
		Conn: c,
	}
}

// construct a mock reader with some number of \n-terminated lines,
// verify that IRCStreamConn can read and split them as expected
func doLineReaderTest(counts []int, t *testing.T) {
	c := newMockConn(counts)
	r := NewIRCStreamConn(c)
	var readCounts []int
	for {
		line, err := r.ReadLine()
		if err == nil {
			readCounts = append(readCounts, len(line))
		} else if err == io.EOF {
			break
		} else {
			panic(err)
		}
	}

	if !reflect.DeepEqual(counts, readCounts) {
		t.Errorf("expected %#v, got %#v", counts, readCounts)
	}
}

const (
	maxMockReaderLen     = 100
	maxMockReaderLineLen = 4096 + 511
)

func TestLineReader(t *testing.T) {
	counts := []int{44, 428, 3, 0, 200, 2000, 0, 4044, 33, 3, 2, 1, 0, 1, 2, 3, 48, 555}
	doLineReaderTest(counts, t)

	// fuzz
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 1000; i++ {
		countsLen := r.Intn(maxMockReaderLen) + 1
		counts := make([]int, countsLen)
		for i := 0; i < countsLen; i++ {
			counts[i] = r.Intn(maxMockReaderLineLen)
		}
		doLineReaderTest(counts, t)
	}
}
