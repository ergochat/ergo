// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import (
	"bytes"
	"regexp"
	"regexp/syntax"
)

// yet another glob implementation in Go

func CompileGlob(glob string) (result *regexp.Regexp, err error) {
	var buf bytes.Buffer
	buf.WriteByte('^')
	for _, r := range glob {
		switch r {
		case '*':
			buf.WriteString("(.*)")
		case '?':
			buf.WriteString("(.)")
		case 0xFFFD:
			return nil, &syntax.Error{Code: syntax.ErrInvalidUTF8, Expr: glob}
		default:
			buf.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	buf.WriteByte('$')
	return regexp.Compile(buf.String())
}
