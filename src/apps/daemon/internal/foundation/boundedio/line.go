// Package boundedio contains small allocation-bounded readers for line-oriented
// control protocols. Callers must treat ErrLineTooLong as a protocol failure;
// some bytes from the offending line have already been consumed.
package boundedio

import (
	"bufio"
	"errors"
	"fmt"
)

var (
	ErrLineTooLong      = errors.New("line exceeds configured byte limit")
	ErrInvalidLineLimit = errors.New("line byte limit must be positive")
)

// ReadLine mirrors bufio.Reader.ReadString('\n') for valid bounded input while
// preventing unbounded growth when a peer never terminates a line. On an
// oversized line it returns no partial payload and ErrLineTooLong.
func ReadLine(r *bufio.Reader, maxBytes int) (string, error) {
	if r == nil {
		return "", fmt.Errorf("nil reader")
	}
	if maxBytes <= 0 {
		return "", ErrInvalidLineLimit
	}
	capacity := r.Size()
	if capacity < 1 {
		capacity = 1
	}
	if capacity > maxBytes {
		capacity = maxBytes
	}
	buf := make([]byte, 0, capacity)
	for {
		fragment, err := r.ReadSlice('\n')
		if len(fragment) > maxBytes-len(buf) {
			return "", ErrLineTooLong
		}
		buf = append(buf, fragment...)
		if err == nil {
			return string(buf), nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return string(buf), err
	}
}
