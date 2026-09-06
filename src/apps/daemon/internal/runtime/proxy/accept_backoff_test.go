package proxy

import (
	"errors"
	"syscall"
	"testing"
	"time"
)

func TestWaitAfterAcceptErrorYieldsAndHonorsShutdown(t *testing.T) {
	done := make(chan struct{})
	start := time.Now()
	if !waitAfterAcceptError(done) {
		t.Fatal("open listener should retry after backoff")
	}
	if elapsed := time.Since(start); elapsed < acceptErrorBackoff/2 {
		t.Fatalf("accept retry returned too quickly: %v", elapsed)
	}

	close(done)
	start = time.Now()
	if waitAfterAcceptError(done) {
		t.Fatal("closed listener owner must not retry")
	}
	if elapsed := time.Since(start); elapsed >= acceptErrorBackoff/2 {
		t.Fatalf("shutdown should interrupt accept backoff: %v", elapsed)
	}
}

func TestAcceptBackoffForErrorDistinguishesFDExhaustion(t *testing.T) {
	if got := acceptBackoffForError(syscall.EMFILE); got != acceptFDExhaustBackoff {
		t.Fatalf("EMFILE got %v", got)
	}
	if got := acceptBackoffForError(syscall.ENFILE); got != acceptFDExhaustBackoff {
		t.Fatalf("ENFILE got %v", got)
	}
	if got := acceptBackoffForError(errors.New("boom")); got != acceptErrorBackoff {
		t.Fatalf("ordinary got %v", got)
	}
}
