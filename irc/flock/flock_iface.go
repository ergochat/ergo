package flock

// documentation for github.com/gofrs/flock incorrectly claims that
// Flock implements sync.Locker; it does not because the Unlock method
// has a return type (err).
type Flocker interface {
	Unlock() error
}

type noopFlocker struct{}

func (n *noopFlocker) Unlock() error {
	return nil
}
