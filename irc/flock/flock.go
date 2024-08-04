//go:build !(plan9 || solaris)

package flock

import (
	"errors"

	"github.com/gofrs/flock"
)

var (
	CouldntAcquire = errors.New("Couldn't acquire flock (is another Ergo running?)")
)

func TryAcquireFlock(path string) (fl Flocker, err error) {
	f := flock.New(path)
	success, err := f.TryLock()
	if err != nil {
		return nil, err
	} else if !success {
		return nil, CouldntAcquire
	}
	return f, nil
}
