//go:build plan9 || solaris

package flock

func TryAcquireFlock(path string) (fl Flocker, err error) {
	return &noopFlocker{}, nil
}
