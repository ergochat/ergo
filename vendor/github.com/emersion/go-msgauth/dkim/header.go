package dkim

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"sort"
	"strings"
)

const crlf = "\r\n"

type header []string

func readHeader(r *bufio.Reader) (header, error) {
	tr := textproto.NewReader(r)

	var h header
	for {
		l, err := tr.ReadLine()
		if err != nil {
			return h, fmt.Errorf("failed to read header: %v", err)
		}

		if len(l) == 0 {
			break
		} else if len(h) > 0 && (l[0] == ' ' || l[0] == '\t') {
			// This is a continuation line
			h[len(h)-1] += l + crlf
		} else {
			h = append(h, l+crlf)
		}
	}

	return h, nil
}

func writeHeader(w io.Writer, h header) error {
	for _, kv := range h {
		if _, err := w.Write([]byte(kv)); err != nil {
			return err
		}
	}
	_, err := w.Write([]byte(crlf))
	return err
}

func foldHeaderField(kv string) string {
	buf := bytes.NewBufferString(kv)

	line := make([]byte, 75) // 78 - len("\r\n\s")
	first := true
	var fold strings.Builder
	for len, err := buf.Read(line); err != io.EOF; len, err = buf.Read(line) {
		if first {
			first = false
		} else {
			fold.WriteString("\r\n ")
		}
		fold.Write(line[:len])
	}

	return fold.String() + crlf
}

func parseHeaderField(s string) (string, string) {
	key, value, _ := strings.Cut(s, ":")
	return strings.TrimSpace(key), strings.TrimSpace(value)
}

func parseHeaderParams(s string) (map[string]string, error) {
	pairs := strings.Split(s, ";")
	params := make(map[string]string)
	for _, s := range pairs {
		key, value, ok := strings.Cut(s, "=")
		if !ok {
			if strings.TrimSpace(s) == "" {
				continue
			}
			return params, errors.New("dkim: malformed header params")
		}

		params[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return params, nil
}

func formatHeaderParams(headerFieldName string, params map[string]string) string {
	keys, bvalue, bfound := sortParams(params)

	s := headerFieldName + ":"
	var line string

	for _, k := range keys {
		v := params[k]
		nextLength := 3 + len(line) + len(v) + len(k)
		if nextLength > 75 {
			s += line + crlf
			line = ""
		}
		line = fmt.Sprintf("%v %v=%v;", line, k, v)
	}

	if line != "" {
		s += line
	}

	if bfound {
		bfiled := foldHeaderField(" b=" + bvalue)
		s += crlf + bfiled
	}

	return s
}

func sortParams(params map[string]string) ([]string, string, bool) {
	keys := make([]string, 0, len(params))
	bfound := false
	var bvalue string
	for k := range params {
		if k == "b" {
			bvalue = params["b"]
			bfound = true
		} else {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, bvalue, bfound
}

type headerPicker struct {
	h      header
	picked map[string]int
}

func newHeaderPicker(h header) *headerPicker {
	return &headerPicker{
		h:      h,
		picked: make(map[string]int),
	}
}

func (p *headerPicker) Pick(key string) string {
	key = strings.ToLower(key)

	at := p.picked[key]
	for i := len(p.h) - 1; i >= 0; i-- {
		kv := p.h[i]
		k, _ := parseHeaderField(kv)

		if !strings.EqualFold(k, key) {
			continue
		}

		if at == 0 {
			p.picked[key]++
			return kv
		}
		at--
	}

	return ""
}
