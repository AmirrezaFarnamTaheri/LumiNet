package proxy

import (
	"errors"
	"testing"
)

type failingEntropyReader struct{}

func (failingEntropyReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func TestPickKRandomIntsFailsClosedWhenEntropyUnavailable(t *testing.T) {
	t.Parallel()

	if got := pickKRandomIntsWithReader(failingEntropyReader{}, 3, 12); got != nil {
		t.Fatalf("pickKRandomIntsWithReader() = %v, want nil on entropy failure", got)
	}
}
