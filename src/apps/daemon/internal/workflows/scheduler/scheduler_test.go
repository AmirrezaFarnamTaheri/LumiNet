package scheduler

import (
	"context"
	"testing"
	"time"
)

func testBudgetPolicy() BudgetPolicy {
	return BudgetPolicy{
		MaxGlobalRunning: 1,
		MaxPerType:       map[JobType]int{"test": 1},
		MaxQueueDepth:    8,
	}
}

func TestSchedulerStopIsIdempotent(t *testing.T) {
	s := NewScheduler(testBudgetPolicy())
	s.Start(context.Background())
	s.Stop()
	s.Stop()
}

func TestSchedulerRejectsSubmitAfterStop(t *testing.T) {
	s := NewScheduler(testBudgetPolicy())
	s.Start(context.Background())
	s.Stop()

	err := s.Submit(NewFuncJob("late", "test", func(context.Context) error { return nil }))
	if err == nil {
		t.Fatal("Submit after Stop succeeded; want scheduler-stopped error")
	}
}

func TestSchedulerStopWaitsForActiveJob(t *testing.T) {
	s := NewScheduler(testBudgetPolicy())
	s.Start(context.Background())

	started := make(chan struct{})
	finished := make(chan struct{})
	job := NewFuncJob("active", "test", func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		time.Sleep(30 * time.Millisecond)
		close(finished)
		return nil
	})
	if err := s.Submit(job); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("job did not start")
	}

	s.Stop()
	select {
	case <-finished:
		// Stop waited for job cleanup.
	default:
		t.Fatal("Stop returned before the active job finished")
	}
}

func TestSchedulerDoesNotAdmitWaitingJobAfterContextCancel(t *testing.T) {
	s := NewScheduler(testBudgetPolicy())
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)

	firstStarted := make(chan struct{})
	first := NewFuncJob("first", "test", func(ctx context.Context) error {
		close(firstStarted)
		<-ctx.Done()
		return nil
	})
	if err := s.Submit(first); err != nil {
		t.Fatalf("submit first: %v", err)
	}
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first job did not start")
	}

	secondStarted := make(chan struct{}, 1)
	second := NewFuncJob("second", "test", func(context.Context) error {
		secondStarted <- struct{}{}
		return nil
	})
	if err := s.Submit(second); err != nil {
		t.Fatalf("submit second: %v", err)
	}

	// Give the dispatcher enough time to dequeue the second job and wait on the
	// saturated budget, then cancel the scheduler parent context.
	time.Sleep(30 * time.Millisecond)
	cancel()
	time.Sleep(30 * time.Millisecond)
	s.Stop()

	select {
	case <-secondStarted:
		t.Fatal("waiting job executed after scheduler context cancellation")
	default:
	}
}

func TestSchedulerRejectsSubmitAfterParentContextCancel(t *testing.T) {
	s := NewScheduler(testBudgetPolicy())
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	cancel()

	err := s.Submit(NewFuncJob("late-after-cancel", "test", func(context.Context) error { return nil }))
	if err == nil {
		t.Fatal("Submit after parent context cancellation succeeded; want admission rejection")
	}
	s.Stop()
}
