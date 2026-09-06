package proxy

import (
	"errors"
	"syscall"
	"time"
)

const (
	acceptErrorBackoff     = 100 * time.Millisecond
	acceptFDExhaustBackoff = 500 * time.Millisecond
)

func acceptBackoffForError(err error) time.Duration {
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
		return acceptFDExhaustBackoff
	}
	return acceptErrorBackoff
}

// waitAfterAcceptError yields after a listener failure while allowing shutdown
// to interrupt the delay immediately. File-descriptor exhaustion gets a longer
// bounded delay to avoid a resource-exhaustion busy loop.
func waitAfterAcceptError(done <-chan struct{}, errs ...error) bool {
	var err error
	if len(errs) > 0 {
		err = errs[0]
	}
	timer := time.NewTimer(acceptBackoffForError(err))
	defer timer.Stop()
	select {
	case <-done:
		return false
	case <-timer.C:
		return true
	}
}
