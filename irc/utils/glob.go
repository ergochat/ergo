// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import (
	"bytes"
	"regexp"
	"strings"
)

// yet another glob implementation in Go

func CompileGlob(glob string) (result *regexp.Regexp, err error) {
	var buf bytes.Buffer
	buf.WriteByte('^')
	for {
		i := strings.IndexByte(glob, '*')
		if i == -1 {
			buf.WriteString(regexp.QuoteMeta(glob))
			break
		} else {
			buf.WriteString(regexp.QuoteMeta(glob[:i]))
			buf.WriteString(".*")
			glob = glob[i+1:]
		}
	}
	buf.WriteByte('$')
	return regexp.Compile(buf.String())
}
