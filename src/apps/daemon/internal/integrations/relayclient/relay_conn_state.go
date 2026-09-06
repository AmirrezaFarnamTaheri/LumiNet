package relayclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const (
	maxRelayQueuedWriteBytes  = 1 << 20
	maxRelayBufferedReadBytes = 1 << 20
	relayRetryBaseDelay       = 250 * time.Millisecond
	relayRetryMaxDelay        = 10 * time.Second
)

// relayConnState hides the virtual net.Conn state shared by polling relay
// adapters. Callers see ordinary net.Conn semantics while this module owns
// bounded buffering, deadline wakeups, close/error propagation, and rollback.
type relayConnState struct {
	mu sync.Mutex

	readBuf bytes.Buffer
	txBuf   bytes.Buffer

	queuedWriteBytes int
	maxWriteBytes    int
	maxReadBytes     int

	closed        bool
	terminalErr   error
	readDeadline  time.Time
	writeDeadline time.Time
	pollFailures  uint8
	idlePollDelay time.Duration

	notify  chan struct{}
	txReady chan struct{}
}

func newRelayConnState() *relayConnState {
	return newRelayConnStateWithLimits(maxRelayQueuedWriteBytes, maxRelayBufferedReadBytes)
}

func newRelayConnStateWithLimits(maxWrite, maxRead int) *relayConnState {
	if maxWrite <= 0 {
		maxWrite = 1
	}
	if maxRead <= 0 {
		maxRead = 1
	}
	return &relayConnState{
		maxWriteBytes: maxWrite,
		maxReadBytes:  maxRead,
		notify:        make(chan struct{}),
		txReady:       make(chan struct{}, 1),
	}
}

func (s *relayConnState) broadcastLocked() {
	close(s.notify)
	s.notify = make(chan struct{})
}

func (s *relayConnState) signalTxReadyLocked() {
	select {
	case s.txReady <- struct{}{}:
	default:
	}
}

func (s *relayConnState) TxReady() <-chan struct{} { return s.txReady }

func (s *relayConnState) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *relayConnState) Close(err error) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.closed = true
	s.terminalErr = err
	s.broadcastLocked()
	return true
}

func waitRelayStateChange(ch <-chan struct{}, deadline time.Time) error {
	if deadline.IsZero() {
		<-ch
		return nil
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return os.ErrDeadlineExceeded
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-ch:
		return nil
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}

func (s *relayConnState) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		s.mu.Lock()
		if s.readBuf.Len() > 0 {
			n, err := s.readBuf.Read(p)
			s.broadcastLocked()
			s.mu.Unlock()
			return n, err
		}
		if s.closed {
			err := s.terminalErr
			s.mu.Unlock()
			if err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
		deadline := s.readDeadline
		wake := s.notify
		s.mu.Unlock()
		if err := waitRelayStateChange(wake, deadline); err != nil {
			return 0, err
		}
	}
}

func (s *relayConnState) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			if written > 0 {
				return written, net.ErrClosed
			}
			return 0, net.ErrClosed
		}
		deadline := s.writeDeadline
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			s.mu.Unlock()
			return written, os.ErrDeadlineExceeded
		}
		available := s.maxWriteBytes - s.queuedWriteBytes
		if available > 0 {
			n := len(p) - written
			if n > available {
				n = available
			}
			_, _ = s.txBuf.Write(p[written : written+n])
			s.queuedWriteBytes += n
			s.idlePollDelay = relayIdlePollBaseDelay
			written += n
			s.signalTxReadyLocked()
			s.mu.Unlock()
			continue
		}
		wake := s.notify
		s.mu.Unlock()
		if err := waitRelayStateChange(wake, deadline); err != nil {
			return written, err
		}
	}
	return written, nil
}

func (s *relayConnState) TakeWriteBatch() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.txBuf.Len() == 0 {
		return nil
	}
	data := append([]byte(nil), s.txBuf.Bytes()...)
	s.txBuf.Reset()
	return data
}

func (s *relayConnState) CommitWrite(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	if n > s.queuedWriteBytes {
		n = s.queuedWriteBytes
	}
	s.queuedWriteBytes -= n
	s.broadcastLocked()
	s.mu.Unlock()
}

func (s *relayConnState) RollbackWrite(data []byte) {
	if len(data) == 0 {
		return
	}
	s.mu.Lock()
	if !s.closed {
		prependFailedWrite(&s.txBuf, data)
		s.signalTxReadyLocked()
	}
	s.broadcastLocked()
	s.mu.Unlock()
}

func (s *relayConnState) ReadBuffered() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readBuf.Len()
}

func (s *relayConnState) AppendRead(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if len(data) > s.maxReadBytes-s.readBuf.Len() {
		err := fmt.Errorf("relay receive buffer exceeds %d bytes", s.maxReadBytes)
		s.closed = true
		s.terminalErr = err
		s.broadcastLocked()
		return err
	}
	_, _ = s.readBuf.Write(data)
	s.idlePollDelay = relayIdlePollBaseDelay
	s.broadcastLocked()
	return nil
}

func (s *relayConnState) RecordPollSuccess() {
	s.mu.Lock()
	s.pollFailures = 0
	s.mu.Unlock()
}

func (s *relayConnState) RecordIdlePoll(emptySuccess bool) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !emptySuccess {
		s.idlePollDelay = relayIdlePollBaseDelay
		return s.idlePollDelay
	}
	if s.idlePollDelay < relayIdlePollBaseDelay {
		s.idlePollDelay = relayIdlePollBaseDelay
	} else if s.idlePollDelay < relayIdlePollMaxDelay {
		s.idlePollDelay *= 2
		if s.idlePollDelay > relayIdlePollMaxDelay {
			s.idlePollDelay = relayIdlePollMaxDelay
		}
	}
	return s.idlePollDelay
}

func (s *relayConnState) RecordPollFailure() time.Duration {
	s.mu.Lock()
	if s.pollFailures < 8 {
		s.pollFailures++
	}
	failures := s.pollFailures
	s.mu.Unlock()
	delay := relayRetryBaseDelay
	for i := uint8(1); i < failures && delay < relayRetryMaxDelay; i++ {
		delay *= 2
		if delay >= relayRetryMaxDelay {
			return relayRetryMaxDelay
		}
	}
	return delay
}

func waitRelayRetry(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (s *relayConnState) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.writeDeadline = t
	s.broadcastLocked()
	s.mu.Unlock()
	return nil
}

func (s *relayConnState) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.broadcastLocked()
	s.mu.Unlock()
	return nil
}

func (s *relayConnState) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.writeDeadline = t
	s.broadcastLocked()
	s.mu.Unlock()
	return nil
}
