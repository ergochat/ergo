// Copyright (c) 2018 Shivaram Lingamneni

package utils

import (
	"io"
	"os"
)

// implementation of `cp` (go should really provide this...)
func CopyFile(src string, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		closeError := out.Close()
		if err == nil {
			err = closeError
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	return
}
