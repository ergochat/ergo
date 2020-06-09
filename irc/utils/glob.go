// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package utils

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

// yet another glob implementation in Go

func addRegexp(buf *strings.Builder, glob string, submatch bool) (err error) {
	for _, r := range glob {
		switch r {
		case '*':
			if submatch {
				buf.WriteString("(.*)")
			} else {
				buf.WriteString(".*")
			}
		case '?':
			if submatch {
				buf.WriteString("(.)")
			} else {
				buf.WriteString(".")
			}
		case 0xFFFD:
			return &syntax.Error{Code: syntax.ErrInvalidUTF8, Expr: glob}
		default:
			buf.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return
}

func CompileGlob(glob string, submatch bool) (result *regexp.Regexp, err error) {
	var buf strings.Builder
	buf.WriteByte('^')
	err = addRegexp(&buf, glob, submatch)
	if err != nil {
		return
	}
	buf.WriteByte('$')
	return regexp.Compile(buf.String())
}

// Compile a list of globs into a single or-expression that matches any one of them.
// This is used for channel ban/invite/exception lists. It's applicable to k-lines
// but we're not using it there yet.
func CompileMasks(masks []string) (result *regexp.Regexp, err error) {
	var buf strings.Builder
	buf.WriteString("^(")
	for i, mask := range masks {
		err = addRegexp(&buf, mask, false)
		if err != nil {
			return
		}
		if i != len(masks)-1 {
			buf.WriteByte('|')
		}
	}
	buf.WriteString(")$")
	return regexp.Compile(buf.String())
}
