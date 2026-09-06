// Package system provides system-level configuration, orchestration, and proxying tools.

package system

import (
	"bufio"
	"context"
	"io"
	"log"
	"os/exec"
	"regexp"
	"sync"
	"time"
)

const (
	maxFailures      = 10
	failureWindow    = time.Hour
	baseRestartDelay = 2 * time.Second
	maxRestartDelay  = 30 * time.Second
	stableReadyRun   = time.Minute
)

// ProcessSupervisor restarts a subprocess on failure with rate limiting and exponential backoff.
type ProcessSupervisor struct {
	name                string
	buildCmd            func() *exec.Cmd
	readyPattern        *regexp.Regexp
	mu                  sync.Mutex
	failureTimes        []time.Time
	consecutiveFailures int
	stableReadyPeriod   time.Duration
}

// NewProcessSupervisor builds a new process supervisor instance.
func NewProcessSupervisor(name string, buildCmd func() *exec.Cmd, readyRe string) *ProcessSupervisor {
	var re *regexp.Regexp
	if readyRe != "" {
		re = regexp.MustCompile(readyRe)
	}
	return &ProcessSupervisor{
		name:              name,
		buildCmd:          buildCmd,
		readyPattern:      re,
		stableReadyPeriod: stableReadyRun,
	}
}

// Run supervises the process until ctx is cancelled.
// readyCh is closed once the process emits the ready string for the first time.
func (s *ProcessSupervisor) Run(ctx context.Context, readyCh chan<- struct{}) {
	firstReady := true
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if pause := s.restartDelay(); pause > 0 {
			log.Printf("[%s] too many failures, pausing for %v", s.name, pause)
			select {
			case <-time.After(pause):
			case <-ctx.Done():
				return
			}
		}

		cmd := s.buildCmd()
		readyFor, err := s.runOnce(ctx, cmd, readyCh, &firstReady)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("[%s] process exited unexpectedly: %v", s.name, err)
		} else {
			log.Printf("[%s] process exited unexpectedly with status 0", s.name)
		}
		s.recordFailureAfterRun(readyFor)
		if s.tooManyFailures() {
			log.Printf("[%s] too many failures in window, giving up", s.name)
			return
		}
	}
}

func restartBackoff(consecutiveFailures int) time.Duration {
	if consecutiveFailures <= 0 {
		return 0
	}
	delay := baseRestartDelay
	for i := 1; i < consecutiveFailures && delay < maxRestartDelay; i++ {
		delay *= 2
		if delay >= maxRestartDelay {
			return maxRestartDelay
		}
	}
	return delay
}

func (s *ProcessSupervisor) restartDelay() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneFailureTimesLocked(time.Now())
	return restartBackoff(s.consecutiveFailures)
}

func (s *ProcessSupervisor) pruneFailureTimesLocked(now time.Time) {
	cutoff := now.Add(-failureWindow)
	fresh := s.failureTimes[:0]
	for _, t := range s.failureTimes {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	s.failureTimes = fresh
}

func (s *ProcessSupervisor) recordFailure() {
	s.recordFailureAfterRun(0)
}

// recordFailureAfterRun resets only exponential-backoff debt after a process
// has remained ready for a meaningful stable interval. A ready-then-crash loop
// therefore keeps escalating, while a genuinely healthy long-running process
// does not carry ancient retry debt forever. The rolling failure history is
// intentionally preserved for the independent circuit breaker.
func (s *ProcessSupervisor) recordFailureAfterRun(readyFor time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.pruneFailureTimesLocked(now)
	if s.stableReadyPeriod > 0 && readyFor >= s.stableReadyPeriod {
		s.consecutiveFailures = 0
	}
	s.failureTimes = append(s.failureTimes, now)
	s.consecutiveFailures++
}

func (s *ProcessSupervisor) tooManyFailures() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneFailureTimesLocked(time.Now())
	return len(s.failureTimes) > maxFailures
}

func (s *ProcessSupervisor) runOnce(ctx context.Context, cmd *exec.Cmd, readyCh chan<- struct{}, firstReady *bool) (time.Duration, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 0, err
	}

	if err := cmd.Start(); err != nil {
		return 0, err
	}
	startedAt := time.Now()
	readyAt := time.Time{}
	if s.readyPattern == nil {
		readyAt = startedAt
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var processReady sync.Once

	readerLoop := func(r io.Reader, label string) {
		defer wg.Done()
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Text()
			log.Printf("[%s:%s] %s", s.name, label, line)
			if s.readyPattern != nil && s.readyPattern.MatchString(line) {
				processReady.Do(func() {
					readyAt = time.Now()
					if firstReady != nil && *firstReady {
						*firstReady = false
						if readyCh != nil {
							close(readyCh)
						}
					}
				})
			}
		}
	}

	go readerLoop(stdout, "stdout")
	go readerLoop(stderr, "stderr")

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		wg.Wait()
		return readyDuration(readyAt, time.Now()), err
	case <-ctx.Done():
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
		wg.Wait()
		return readyDuration(readyAt, time.Now()), ctx.Err()
	}
}

func readyDuration(readyAt, endedAt time.Time) time.Duration {
	if readyAt.IsZero() || endedAt.Before(readyAt) {
		return 0
	}
	return endedAt.Sub(readyAt)
}
